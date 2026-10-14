"""Known vulnerabilities (CVE) of the installed packages: Grype on the controller + verification on the target.

Nothing is installed on the target:
  1. the target provides its OS (/etc/os-release), the installed packages (dpkg-query or rpm -qa)
     and the updates AVAILABLE right now (apt list --upgradable or dnf check-update);
  2. the controller writes a CycloneDX SBOM (the package list in a standard format) and passes it
     to Grype, which matches it against its vulnerability database;
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
if command -v dpkg-query >/dev/null 2>&1; then
  echo "KIND|deb"
  dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' \
    2>/dev/null | awk -F'\t' '$1 ~ /^ii/ {print "PKG|" $2 "|" $3 "|" $4 "|" $5 "|" $6}'
  apt list --upgradable 2>/dev/null | awk -F'[/ ]' 'NF>2 && $1 != "Listing..." {print "AVAIL|" $1 "|" $3}'
elif command -v rpm >/dev/null 2>&1; then
  echo "KIND|rpm"
  rpm -qa --qf 'PKG|%{NAME}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}|%{ARCH}|%{SOURCERPM}|\n' 2>/dev/null | grep -v '^PKG|gpg-pubkey|'
  (dnf -q check-update 2>/dev/null || yum -q check-update 2>/dev/null) | awk 'NF==3 && $1 ~ /\./ {print "AVAIL|" $1 "|" $2}'
fi
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
            name = p[1]
            if d["kind"] == "rpm":
                name = name.rsplit(".", 1)[0]          # "openssl-libs.x86_64" -> "openssl-libs"
            d["avail"][name] = p[2].strip()
    return d


def _purl(inv: dict, p: dict) -> str:
    distro = f"{inv['os']}-{inv['version']}"
    if inv["kind"] == "deb":
        q = f"arch={p['arch']}"
        if p["source"] and p["source"] != p["name"]:
            up = p["source"] + (f"@{p['source_version']}" if p["source_version"] and p["source_version"] != p["version"] else "")
            q += "&upstream=" + quote(up, safe="")
        return f"pkg:deb/{inv['os']}/{quote(p['name'], safe='')}@{quote(p['version'], safe='')}?{q}&distro={distro}"
    epoch, _, vr = p["version"].partition(":") if ":" in p["version"] else ("0", "", p["version"])
    q = f"arch={p['arch']}" + (f"&epoch={epoch}" if epoch not in ("", "0") else "")
    if p["source"] and p["source"] != "(none)":
        q += "&upstream=" + quote(p["source"], safe="")
    return f"pkg:rpm/{inv['os']}/{quote(p['name'], safe='')}@{quote(vr, safe='')}?{q}&distro={distro}"


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
                    "The reference distribution vendor (e.g. Red Hat for Rocky) has the fix, but this system's "
                    "repository does not yet: check again in a few days. Packages: "
                    + ", ".join(pk[:20])))
    if c["unfixed"]:
        cnt = {s: sum(1 for v in c["unfixed"] if v["severity"] == s) for s in ORDER}
        out.append(("info", f"{len(c['unfixed'])} CVEs without a fix from the distribution",
                    "No update resolves them today: the distribution often rates them as minimal impact "
                    "or fixes them later. By severity: " + ", ".join(f"{s} {n}" for s, n in cnt.items() if n)))
    return out
