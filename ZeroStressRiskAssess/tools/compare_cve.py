#!/usr/bin/env python3
"""Compare Trivy and Grype results for the SAME image or machine.

Usage (on the controller, with the lab images already built):
    trivy image --scanners vuln --format json -o trivy.json zerostressriskassess-lab-severe:24.04
    grype zerostressriskassess-lab-severe:24.04 -o json > grype.json
    python3 tools/compare_cve.py trivy.json grype.json [--details]

Measures:
  - how many vulnerabilities each scanner reports, counted by CVE (Grype sometimes reports the
    distribution advisory, e.g. RHSA/ALSA, with the related CVEs: the CVEs are used, as Trivy does);
  - how many are found by BOTH and by only one, split into "fix available" (resolved by updating)
    and "no fix" (the distribution has not released a patch yet);
  - how many shared CVEs have a different severity in the two scanners.
"""
from __future__ import annotations

import json
import sys
from collections import Counter

SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "NEGLIGIBLE": "low",
       "UNKNOWN": "unknown"}


def load(path):
    """Parsed JSON of the file, or exit with a readable message (an empty file means an interrupted scan)."""
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        sys.exit(f"ERROR: {path}: {e.strerror}")
    if not text.strip():
        sys.exit(f"ERROR: {path} is EMPTY. With '> file' the shell truncates the file as soon as the command starts: "
                 "if the scan is interrupted (Ctrl-C, error) it stays empty. Run it again until it completes.")
    try:
        return json.loads(text)
    except ValueError as e:
        sys.exit(f"ERROR: {path} is not valid JSON ({e}). Is it the output of '-o json' / '--format json'?")


def trivy(path):
    """{(cve, package): (severity, has_fix)}"""
    out = {}
    for r in load(path).get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            out[(v["VulnerabilityID"], v["PkgName"])] = (SEV.get(v.get("Severity", "").upper(), "unknown"),
                                                         bool(v.get("FixedVersion")),
                                                         v.get("InstalledVersion", ""), v.get("FixedVersion", ""))
    return out


def grype(path):
    out = {}
    for m in load(path).get("matches") or []:
        v, art = m["vulnerability"], m["artifact"]
        ids = [v["id"]] if v["id"].startswith("CVE-") else \
            [r["id"] for r in m.get("relatedVulnerabilities") or [] if r["id"].startswith("CVE-")] or [v["id"]]
        fix = v.get("fix") or {}
        fixed = fix.get("state") == "fixed"
        for i in ids:
            out[(i, art["name"])] = (SEV.get(v.get("severity", "").upper(), "unknown"), fixed,
                                     art.get("version", ""), ",".join(fix.get("versions") or []))
    return out


def compare(t, g):
    both, only_t, only_g = t.keys() & g.keys(), t.keys() - g.keys(), g.keys() - t.keys()
    r = {"trivy": len(t), "grype": len(g), "both": len(both), "only_trivy": len(only_t), "only_grype": len(only_g),
         "only_trivy_fixable": sum(1 for k in only_t if t[k][1]),
         "only_grype_fixable": sum(1 for k in only_g if g[k][1]),
         "severity_mismatch": sum(1 for k in both if t[k][0] != g[k][0]),
         "examples_only_trivy": sorted(only_t)[:8], "examples_only_grype": sorted(only_g)[:8],
         "severity_trivy": Counter(v[0] for v in t.values()), "severity_grype": Counter(v[0] for v in g.values()),
         "mismatch_matrix": Counter((t[k][0], g[k][0]) for k in both if t[k][0] != g[k][0]),
         "grype_fixable": sorted((k, g[k][2], g[k][3]) for k in only_g if g[k][1]),
         "trivy_fixable": sorted((k, t[k][2], t[k][3]) for k in only_t if t[k][1])}
    return r


def main(argv):
    argv = [a for a in argv if a != "--details"] + (["--details"] if "--details" in argv else [])
    if len(argv) not in (3, 4):
        print(__doc__)
        return 2
    r = compare(trivy(argv[1]), grype(argv[2]))
    print(f"Trivy: {r['trivy']}  Grype: {r['grype']}  (CVE+package pairs)")
    print(f"In common: {r['both']}  only Trivy: {r['only_trivy']} (fixable {r['only_trivy_fixable']})"
          f"  only Grype: {r['only_grype']} (fixable {r['only_grype_fixable']})")
    print(f"Different severity on shared CVEs: {r['severity_mismatch']}")
    print("Trivy severities:", dict(r["severity_trivy"]), " Grype:", dict(r["severity_grype"]))
    print("Examples only in Trivy:", r["examples_only_trivy"])
    print("Examples only in Grype:", r["examples_only_grype"])
    if r["mismatch_matrix"]:
        print("\nDifferent severity (Trivy -> Grype: count):")
        for (a, b), n in r["mismatch_matrix"].most_common():
            print(f"  {a:>8} -> {b:<8} {n}")
    if "--details" in argv:
        # Most relevant: fixable findings reported by one scanner only. They are resolved by updating, provided
        # the fix really exists for this distribution (on RHEL-like systems Grype relies on Red Hat data).
        for name, rows in (("Grype", r["grype_fixable"]), ("Trivy", r["trivy_fixable"])):
            if rows:
                print(f"\nOnly {name}, WITH a fix ({len(rows)}): CVE, package, installed -> fixed in")
                for (cve, pkg), inst, fix in rows:
                    print(f"  {cve:<18} {pkg:<28} {inst} -> {fix}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
