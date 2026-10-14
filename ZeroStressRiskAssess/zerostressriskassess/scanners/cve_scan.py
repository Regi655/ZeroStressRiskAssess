""""cve" check: known vulnerabilities of the installed packages (see zerostressriskassess/cve.py)."""
from __future__ import annotations

import shutil

from .. import cve
from ..models import ScanResult


def run(ctx) -> ScanResult:
    res = ScanResult("cve")
    if not shutil.which("grype"):
        return res.skip("grype not installed on the controller (see README, Requirements section)")
    inv = cve.parse_inventory(ctx.rem.run(cve.INVENTORY, sudo=True, timeout=300).out)
    if not inv["pkgs"] or not inv["os"]:
        return res.skip("package list cannot be read on the target")
    data, err = cve.run_grype(inv, timeout=ctx.opts.scan_timeout)
    if data is None:
        res.status = "error"
        res.add("info", "Grype produced no results", err)
        return res
    c = cve.classify(cve.parse_grype(data), inv["avail"], inv["kind"])
    res.data.update({"os": f"{inv['os']} {inv['version']}", "packages": len(inv["pkgs"]),
                     "available_updates": len(inv["avail"]), "now": len(c["now"]),
                     "waiting": len(c["waiting"]), "unfixed": len(c["unfixed"]),
                     "grype_db": cve.db_info(data)})
    # Details for the risk model (KEV, CVSS vector) and for the CVE table in the report.
    res.data["now_detail"] = [{k: v[k] for k in ("cve", "pkg", "severity", "kev", "cvss", "installed", "available")}
                              for v in c["now"][:2000]]
    for sev, title, detail in cve.evaluate(c):
        res.add(sev, title, detail)
    return res
