"""Known vulnerabilities (CVE) of the installed packages: Grype and/or Trivy on the controller + verification on
the target.

Nothing is installed on the target:
  1. the target provides its OS (/etc/os-release), the installed packages (dpkg-query)
     and the updates AVAILABLE right now (apt list --upgradable);
  2. the controller writes a CycloneDX SBOM (the package list in a standard format) and passes it
     to Grype and/or Trivy, which match it against their vulnerability databases. When both are installed the
     results are merged: the same CVE on the same package counts once, and each entry records which scanner
     found it (the two databases do not fully overlap);
  3. every CVE "with a fix" is compared with the version available on the target (vercmp.py).

Step 3 is needed because a fix published upstream is not necessarily installable yet on the target.
In a lab comparison (October 2026) Grype reported 48 CVEs with a fix that no other source flagged:
33 were installable immediately, 15 were not yet available for that distribution. Only asking the
target "which version can you install now?" separates the two cases.
CVEs without any fix are reported as a count: no update can resolve them, and listing them one
per line would bury the actionable items.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from urllib.parse import quote

from .vercmp import compare

INVENTORY = r"""
. /etc/os-release 2>/dev/null; echo "OS|${ID}|${VERSION_ID}"
echo "KIND|deb"
dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' \
  2>/dev/null | awk -F'\t' '$1 ~ /^ii/ {print "PKG|" $2 "|" $3 "|" $4 "|" $5 "|" $6}'
apt list --upgradable 2>/dev/null | awk -F'[/ ]' 'NF>2 && $1 != "Listing..." {print "AVAIL|" $1 "|" $3}'
"""

SEV_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "negligible": "low",
           "unknown": "low"}
ORDER = ["critical", "high", "medium", "low"]


def parse_inventory(text: str) -> dict:
    """INVENTORY output -> {"os", "version", "kind", "pkgs": [...], "avail": {name: version}}. Pure function."""
    d = {"os": "", "version": "", "kind": "", "pkgs": [], "avail": {}}
    for line in text.splitlines():
        p = line.split("|")
        if p[0] == "OS" and len(p) >= 3:
            d["os"], d["version"] = p[1].strip().lower(), p[2].strip()
        elif p[0] == "KIND" and len(p) >= 2:
            d["kind"] = p[1].strip()
        elif p[0] == "PKG" and len(p) >= 5 and p[1]:
            d["pkgs"].append({"name": p[1], "version": p[2], "arch": p[3], "source": p[4],
                              "source_version": p[5] if len(p) > 5 else ""})
        elif p[0] == "AVAIL" and len(p) >= 3:
            d["avail"][p[1]] = p[2].strip()
    return d


def _purl(inv: dict, p: dict) -> str:
    distro = f"{inv['os']}-{inv['version']}"
    q = f"arch={p['arch']}"
    if p["source"] and p["source"] != p["name"]:
        up = p["source"] + (f"@{p['source_version']}" if p["source_version"] and p["source_version"] != p["version"] else "")
        q += "&upstream=" + quote(up, safe="")
    return f"pkg:deb/{inv['os']}/{quote(p['name'], safe='')}@{quote(p['version'], safe='')}?{q}&distro={distro}"


def cyclonedx(inv: dict) -> dict:
    """CycloneDX 1.4 SBOM with the system packages and the operating system as a component."""
    comps = [{"type": "operating-system", "name": inv["os"], "version": inv["version"]}]
    for p in inv["pkgs"]:
        comps.append({"type": "library", "name": p["name"], "version": p["version"], "purl": _purl(inv, p)})
    return {"bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1,
            "metadata": {"component": {"type": "operating-system", "name": inv["os"], "version": inv["version"]}},
            "components": comps}


def db_info(data: dict) -> str:
    """Grype version and database date, from the "descriptor" of the JSON output. Pure function.

    The field changed between releases: up to schema v5 it was descriptor.db.built, from schema v6
    (Grype 0.88 and later) it is descriptor.db.status.built. If missing, only the version is returned.
    """
    d = data.get("descriptor") or {}
    db = d.get("db") or {}
    built = db.get("built") or (db.get("status") or {}).get("built") or ""
    parts = [f"v{d['version']}" if d.get("version") else "", f"database of {str(built)[:10]}" if built else ""]
    return ", ".join(x for x in parts if x)


def run_grype(inv: dict, timeout: int = 900):
    """(Grype JSON | None, message). Grype runs on the CONTROLLER."""
    exe = shutil.which("grype")
    if not exe:
        return None, "grype not installed on the controller"
    with tempfile.NamedTemporaryFile("w", suffix=".cdx.json", delete=False) as f:
        json.dump(cyclonedx(inv), f)
        path = f.name
    try:
        p = subprocess.run([exe, f"sbom:{path}", "--distro", f"{inv['os']}:{inv['version']}", "-o", "json"],
                           capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, "GRYPE_CHECK_FOR_APP_UPDATE": "false"})
    finally:
        os.unlink(path)
    try:
        return json.loads(p.stdout), ""
    except ValueError:
        return None, (p.stderr or p.stdout)[-300:]


def parse_grype(data: dict) -> list:
    """Grype matches -> [{cve, pkg, installed, severity, state, fix: [versions], kev, cvss}]. Pure function.
    Distribution advisories (RHSA, ALSA...) are mapped to their related CVEs, consistently with the
    Trivy comparison (tools/compare_cve.py).
    """
    out, seen = [], set()
    for m in data.get("matches") or []:
        v, art = m.get("vulnerability") or {}, m.get("artifact") or {}
        vid = v.get("id", "")
        ids = [vid] if vid.startswith("CVE-") else \
            [r["id"] for r in m.get("relatedVulnerabilities") or [] if str(r.get("id", "")).startswith("CVE-")] or [vid]
        fix = v.get("fix") or {}
        vectors = [c.get("vector", "") for c in v.get("cvss") or [] if c.get("vector")]
        for cve in ids:
            key = (cve, art.get("name"))
            if key in seen:
                continue
            seen.add(key)
            out.append({"cve": cve, "pkg": art.get("name", "?"), "installed": art.get("version", ""),
                        "severity": SEV_MAP.get(str(v.get("severity", "unknown")).lower(), "low"),
                        "state": fix.get("state", "unknown"), "fix": list(fix.get("versions") or []),
                        "kev": bool(v.get("knownExploited")), "cvss": vectors[:1]})
    return out


def classify(vulns: list, avail: dict, kind: str) -> dict:
    """Split CVEs into: fixable NOW (the fixed version is available on the target), pending (fixed
    elsewhere, e.g. upstream, but not yet for this system), and without a fix. Pure function.
    """
    r = {"now": [], "waiting": [], "unfixed": []}
    for v in vulns:
        if v["state"] != "fixed" or not v["fix"]:
            r["unfixed"].append(v)
            continue
        cand = avail.get(v["pkg"])
        fix = min(v["fix"], key=lambda x, k=kind: _key(x, k))
        if cand and compare(_norm(cand, kind), _norm(fix, kind), kind) >= 0:
            r["now"].append({**v, "available": cand, "fix_min": fix})
        else:
            r["waiting"].append({**v, "available": cand or "", "fix_min": fix})
    return r


def _norm(v: str, kind: str) -> str:
    # Grype reports "0:10.40-7.el9_8", dnf "10.40-7.el9_8": an explicit or missing epoch 0 is the same.
    return v[2:] if kind == "rpm" and v.startswith("0:") else v


class _key:
    """Sort key for min() using the version comparison of the package type."""
    def __init__(self, v, kind):
        self.v, self.kind = _norm(v, kind), kind

    def __lt__(self, other):
        return compare(self.v, other.v, self.kind) < 0


def evaluate(c: dict) -> list:
    """[(severity, title, detail)]: one line per package for CVEs fixable now, one line each for
    "pending" and "no fix". Pure function.
    """
    out = []
    by_pkg = {}
    for v in c["now"]:
        by_pkg.setdefault(v["pkg"], []).append(v)
    for pkg, vs in sorted(by_pkg.items(), key=lambda kv: (min(ORDER.index(v["severity"]) for v in kv[1]), kv[0])):
        sev = min((v["severity"] for v in vs), key=ORDER.index)
        kev = [v["cve"] for v in vs if v["kev"]]
        if kev:
            sev = "critical"
        cves = sorted({v["cve"] for v in vs})
        out.append((sev, f"{pkg}: {len(cves)} CVEs fixed by the update already available ({vs[0]['available']})",
                    (f"ACTIVELY EXPLOITED (CISA KEV catalogue): {', '.join(kev)}. " if kev else "")
                    + f"Installed {vs[0]['installed']}. CVEs: {', '.join(cves[:12])}"
                    + (f" and {len(cves) - 12} more" if len(cves) > 12 else "")))
    if c["waiting"]:
        pk = sorted({v["pkg"] for v in c["waiting"]})
        out.append(("info", f"{len(c['waiting'])} CVEs fixed upstream but without an update available here yet",
                    "The fix exists (upstream or in the distribution's tracker), but this system's repository does "
                    "not offer it yet: check again in a few days. Packages: "
                    + ", ".join(pk[:20])))
    if c["unfixed"]:
        cnt = {s: sum(1 for v in c["unfixed"] if v["severity"] == s) for s in ORDER}
        out.append(("info", f"{len(c['unfixed'])} CVEs without a fix from the distribution",
                    "No update resolves them today: the distribution often rates them as minimal impact "
                    "or fixes them later. By severity: " + ", ".join(f"{s} {n}" for s, n in cnt.items() if n)))
    return out


# --------------------------------------------------------------------------------------------- Trivy
# Trivy releases known to be malicious. v0.69.4 was published with stolen credentials on 2026-03-19
# (supply-chain attack, CVE-2026-33634): it is never executed, even if installed.
COMPROMISED_TRIVY = {"0.69.4"}


def _split_deb(v: str):
    """Debian version -> (epoch, upstream, revision): "1:2.3-4ubuntu1" -> ("1", "2.3", "4ubuntu1"). Pure function."""
    epoch, _, rest = v.partition(":") if ":" in v else ("", "", v)
    up, sep, rev = rest.rpartition("-")
    return (epoch, up, rev) if sep else (epoch, rest, "")


def cyclonedx_trivy(inv: dict) -> dict:
    """CycloneDX SBOM in the shape Trivy produces for a file system, so that `trivy sbom` reads it as OS packages.

    Differences from cyclonedx() (used for Grype, unchanged):
      - the operating system is a component the packages depend on ("dependencies"): Trivy attaches packages
        to an OS through the dependency graph;
      - every package carries Trivy's own properties (aquasecurity:trivy:SrcName, SrcVersion, SrcRelease,
        SrcEpoch, PkgType). Ubuntu and Debian publish advisories per SOURCE package (e.g. "openssl", not the
        binary "libssl3t64"): without these properties Trivy would look up the binary name and miss them.
    """
    def prop(name, value):
        return {"name": f"aquasecurity:trivy:{name}", "value": str(value)}

    comps, refs = [{"bom-ref": "os", "type": "operating-system", "name": inv["os"], "version": inv["version"]}], []
    for i, p in enumerate(inv["pkgs"]):
        ref = f"pkg-{i}"
        src = p["source"] or p["name"]
        epoch, ver, rel = _split_deb(p["source_version"] or p["version"])
        props = [prop("PkgType", inv["os"]), prop("SrcName", src), prop("SrcVersion", ver)]
        if rel:
            props.append(prop("SrcRelease", rel))
        if epoch not in ("", "0"):
            props.append(prop("SrcEpoch", epoch))
        comps.append({"bom-ref": ref, "type": "library", "name": p["name"], "version": p["version"],
                      "purl": _purl(inv, p), "properties": props})
        refs.append(ref)
    deps = [{"ref": "root", "dependsOn": ["os"]}, {"ref": "os", "dependsOn": refs}] + \
        [{"ref": r, "dependsOn": []} for r in refs]
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"bom-ref": "root", "type": "application", "name": "zerostressriskassess-inventory"}},
            "components": comps, "dependencies": deps}


def trivy_info(data: dict) -> str:
    """Trivy version and database date, from `trivy version --format json`. Pure function."""
    db = data.get("VulnerabilityDB") or {}
    parts = [f"v{data['Version']}" if data.get("Version") else "",
             f"database of {str(db['UpdatedAt'])[:10]}" if db.get("UpdatedAt") else ""]
    return ", ".join(x for x in parts if x)


def run_trivy(inv: dict, timeout: int = 900):
    """(Trivy JSON | None, version info, message). Trivy runs on the CONTROLLER, offline from the target."""
    exe = shutil.which("trivy")
    if not exe:
        return None, "", "trivy not installed on the controller"
    env = {**os.environ, "TRIVY_DISABLE_VEX_NOTICE": "true"}
    try:
        ver = json.loads(subprocess.run([exe, "version", "--format", "json"], capture_output=True, text=True,
                                        timeout=60, env=env).stdout or "{}")
    except (ValueError, subprocess.TimeoutExpired):
        ver = {}
    if ver.get("Version") in COMPROMISED_TRIVY:
        return None, trivy_info(ver), (f"Trivy {ver['Version']} is the compromised release (CVE-2026-33634) and was NOT "
                                       "run. Remove it, treat the secrets reachable from this machine as exposed, and "
                                       "install a clean release from Aqua's signed repository.")
    with tempfile.NamedTemporaryFile("w", suffix=".cdx.json", delete=False) as f:
        json.dump(cyclonedx_trivy(inv), f)
        path = f.name
    try:
        p = subprocess.run([exe, "sbom", "--scanners", "vuln", "--format", "json", "--quiet", path],
                           capture_output=True, text=True, timeout=timeout, env=env)
    finally:
        os.unlink(path)
    try:
        return json.loads(p.stdout), trivy_info(ver), ""
    except ValueError:
        return None, trivy_info(ver), (p.stderr or p.stdout)[-300:]


def parse_trivy(data: dict) -> list:
    """Trivy results -> the same records as parse_grype(). Pure function.

    Trivy has no KEV information (kev is always False here; merge() propagates it from Grype when both run).
    FixedVersion may list several versions separated by commas; Status is kept as the state when there is no fix
    (e.g. "affected", "will_not_fix", "fix_deferred").
    """
    out, seen = [], set()
    for r in data.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            key = (v.get("VulnerabilityID", ""), v.get("PkgName", "?"))
            if key in seen:
                continue
            seen.add(key)
            fixes = [x.strip() for x in str(v.get("FixedVersion") or "").split(",") if x.strip()]
            cvss = v.get("CVSS") or {}
            vectors = [c.get("V3Vector") for _, c in sorted(cvss.items(), key=lambda kv: kv[0] != "nvd")
                       if isinstance(c, dict) and c.get("V3Vector")]
            out.append({"cve": key[0], "pkg": key[1], "installed": v.get("InstalledVersion", ""),
                        "severity": SEV_MAP.get(str(v.get("Severity", "unknown")).lower(), "low"),
                        "state": "fixed" if fixes else (v.get("Status") or "unknown"), "fix": fixes,
                        "kev": False, "cvss": vectors[:1]})
    return out


def merge(grype=None, trivy=None) -> list:
    """Union of the Grype and Trivy records, one per (CVE, package), with "sources". Pure function.

    When both report the same pair: the more severe rating is kept (conservative), the entry counts as fixed if
    either knows a fix (classify() then checks whether that fix is really installable on the target), and the
    first CVSS vector available is kept. KEV is a property of the CVE: if Grype marks it, every package affected
    by that CVE is marked, including those only Trivy found.
    """
    by = {}
    for src, records in (("grype", grype or []), ("trivy", trivy or [])):
        for v in records:
            k = (v["cve"], v["pkg"])
            cur = by.get(k)
            if cur is None:
                by[k] = {**v, "fix": list(v["fix"]), "sources": [src]}
                continue
            cur["sources"].append(src)
            cur["severity"] = min(cur["severity"], v["severity"], key=ORDER.index)
            if v["state"] == "fixed":
                cur["fix"] = sorted(set(cur["fix"]) | set(v["fix"]))
                cur["state"] = "fixed"
            cur["cvss"] = cur["cvss"] or v["cvss"]
    kev = {v["cve"] for v in by.values() if v["kev"]}
    for v in by.values():
        v["kev"] = v["cve"] in kev
    return list(by.values())


def sources_text(data: dict) -> str:
    """Line describing the CVE sources for the report (data = the cve check's data). Pure function."""
    src = data.get("sources") or ["Grype " + (data.get("grype_db") or "(version not detected)")]
    text = "; ".join(src)
    ov = data.get("overlap")
    if ov:
        text += (f". CVE+package pairs found by both: {ov['both']}, only by Grype: {ov['only_grype']}, "
                 f"only by Trivy: {ov['only_trivy']}")
    if not any(s.startswith("Grype") for s in src):
        text += ". KEV data comes from Grype only: without it the KEV column stays empty"
    return text
