#!/usr/bin/env python3
"""Compare Trivy and Grype results for the SAME image or machine.

Usage (on the controller, with the lab images already built):
    trivy image --scanners vuln --format json -o trivy.json zerostressriskassess-lab-grave:24.04
    grype zerostressriskassess-lab-grave:24.04 -o json > grype.json
    python3 tools/confronta_cve.py trivy.json grype.json [--dettagli]

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
        sys.exit(f"ERRORE: {path}: {e.strerror}")
    if not text.strip():
        sys.exit(f"ERRORE: {path} è VUOTO. Con '> file' la shell svuota il file appena parte il comando: "
                 "se la scansione si interrompe (Ctrl-C, errore) resta vuoto. Rilanciala fino alla fine.")
    try:
        return json.loads(text)
    except ValueError as e:
        sys.exit(f"ERRORE: {path} non è un JSON valido ({e}). È l'output di '-o json' / '--format json'?")


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
    r = {"trivy": len(t), "grype": len(g), "entrambi": len(both), "solo_trivy": len(only_t), "solo_grype": len(only_g),
         "solo_trivy_con_fix": sum(1 for k in only_t if t[k][1]),
         "solo_grype_con_fix": sum(1 for k in only_g if g[k][1]),
         "gravita_diversa": sum(1 for k in both if t[k][0] != g[k][0]),
         "esempi_solo_trivy": sorted(only_t)[:8], "esempi_solo_grype": sorted(only_g)[:8],
         "gravita_trivy": Counter(v[0] for v in t.values()), "gravita_grype": Counter(v[0] for v in g.values()),
         "matrice": Counter((t[k][0], g[k][0]) for k in both if t[k][0] != g[k][0]),
         "grype_con_fix": sorted((k, g[k][2], g[k][3]) for k in only_g if g[k][1]),
         "trivy_con_fix": sorted((k, t[k][2], t[k][3]) for k in only_t if t[k][1])}
    return r


def main(argv):
    argv = [a for a in argv if a != "--dettagli"] + (["--dettagli"] if "--dettagli" in argv else [])
    if len(argv) not in (3, 4):
        print(__doc__)
        return 2
    r = compare(trivy(argv[1]), grype(argv[2]))
    print(f"Trivy: {r['trivy']}  Grype: {r['grype']}  (coppie CVE+pacchetto)")
    print(f"In comune: {r['entrambi']}  solo Trivy: {r['solo_trivy']} (con correzione {r['solo_trivy_con_fix']})"
          f"  solo Grype: {r['solo_grype']} (con correzione {r['solo_grype_con_fix']})")
    print(f"Gravità diversa sulle CVE in comune: {r['gravita_diversa']}")
    print("Gravità Trivy:", dict(r["gravita_trivy"]), " Grype:", dict(r["gravita_grype"]))
    print("Esempi solo Trivy:", r["esempi_solo_trivy"])
    print("Esempi solo Grype:", r["esempi_solo_grype"])
    if r["matrice"]:
        print("\nGravità diversa (Trivy -> Grype: quante):")
        for (a, b), n in r["matrice"].most_common():
            print(f"  {a:>8} -> {b:<8} {n}")
    if "--dettagli" in argv:
        # Most relevant: fixable findings reported by one scanner only. They are resolved by updating, provided
        # the fix really exists for this distribution (on RHEL-like systems Grype relies on Red Hat data).
        for name, rows in (("Grype", r["grype_con_fix"]), ("Trivy", r["trivy_con_fix"])):
            if rows:
                print(f"\nSolo {name}, CON correzione ({len(rows)}): CVE, pacchetto, installata -> corretta in")
                for (cve, pkg), inst, fix in rows:
                    print(f"  {cve:<18} {pkg:<28} {inst} -> {fix}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
