""""cve" check: known vulnerabilities of the installed packages (see zerostressriskassess/cve.py).

Uses Grype, Trivy or both, whichever is installed on the controller. With both, the results are merged.
"""
from __future__ import annotations

import shutil

from .. import cve
from ..models import ScanResult


def run(ctx) -> ScanResult:
    res = ScanResult("cve")
    tools = [t for t in ("grype", "trivy") if shutil.which(t)]
    if not tools:
        return res.skip("neither grype nor trivy installed on the controller (see README, Requirements section)")
    inv = cve.parse_inventory(ctx.rem.run(cve.INVENTORY, sudo=True, timeout=300).out)
    if not inv["pkgs"] or not inv["os"]:
        return res.skip("package list cannot be read on the target")

    found, sources, failed = {}, [], []
    if "grype" in tools:
        data, err = cve.run_grype(inv, timeout=ctx.opts.scan_timeout)
        if data is None:
            failed.append(("Grype", err))
        else:
            found["grype"] = cve.parse_grype(data)
            sources.append("Grype " + (cve.db_info(data) or "(version not detected)"))
            res.data["grype_db"] = cve.db_info(data)
    if "trivy" in tools:
        data, info, err = cve.run_trivy(inv, timeout=ctx.opts.scan_timeout)
        if data is None:
            failed.append(("Trivy", err))
        else:
            found["trivy"] = cve.parse_trivy(data)
            sources.append("Trivy " + (info or "(version not detected)"))
            res.data["trivy_db"] = info
    for name, err in failed:
        res.add("info", f"{name} produced no results", err)
    if not found:
        res.status = "error"
        return res

    vulns = cve.merge(found.get("grype"), found.get("trivy"))
    c = cve.classify(vulns, inv["avail"], inv["kind"])
    res.data.update({"os": f"{inv['os']} {inv['version']}", "packages": len(inv["pkgs"]),
                     "available_updates": len(inv["avail"]), "now": len(c["now"]),
                     "waiting": len(c["waiting"]), "unfixed": len(c["unfixed"]), "sources": sources})
    if len(found) == 2:
        # How much the two databases overlap (CVE+package pairs): shown in the report next to the sources.
        res.data["overlap"] = {"both": sum(1 for v in vulns if len(v["sources"]) == 2),
                               "only_grype": sum(1 for v in vulns if v["sources"] == ["grype"]),
                               "only_trivy": sum(1 for v in vulns if v["sources"] == ["trivy"])}
    # Details for the risk model (KEV, CVSS vector) and for the CVE table in the report.
    res.data["now_detail"] = [{k: v[k] for k in ("cve", "pkg", "severity", "kev", "cvss", "installed", "available",
                                                 "sources")}
                              for v in c["now"][:2000]]
    for sev, title, detail in cve.evaluate(c):
        res.add(sev, title, detail)
    return res
