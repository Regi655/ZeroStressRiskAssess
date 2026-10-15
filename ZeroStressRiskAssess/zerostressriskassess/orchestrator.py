"""Orchestrator: the whole assessment in a single command, in the correct order.

1. EXTERNAL checks from the controller (nmap with NSE scripts, ssh-audit), BEFORE touching the
   target: the view of an attacker coming from the network;
2. connection (SSH, or none with --local) and root privilege check;
3. operating system (Ubuntu/Debian) and container detection;
4. ClamAV installed on the target if needed     } inside try/finally: cleanup
5. INTERNAL checks (including portable Lynis)   } ALWAYS runs, even on errors
6. removal of everything that was installed     } or Ctrl-C
7. findings -> issues -> impact x likelihood -> HTML, Markdown and JSON reports.
"""
from __future__ import annotations

import time
from datetime import datetime

from . import __version__
from .models import Context, Options, ScanResult
from .osinfo import detect
from .htmlreport import to_html
from .report import build_report, save, to_markdown
from .scanners import EXTERNAL, INTERNAL
from .toolmgr import ToolManager, recover_interrupted


def _run_scanner(name, fn, ctx, log) -> ScanResult:
    log(f"[+] {name} ...")
    t0 = time.time()
    try:
        res = fn(ctx)
    except Exception as exc:  # a failing check must not stop the others
        res = ScanResult(name, status="error")
        res.add("info", f"Check failed: {type(exc).__name__}: {exc}")
    res.name = name
    res.duration = time.time() - t0
    log(f"    -> {res.status}, {len(res.findings)} findings ({res.duration:.0f}s)")
    return res


def risk_context(results, opts: Options, rem) -> dict:
    """What the risk model needs to know about what the tool actually MEASURED."""
    by = {r.name: r for r in results}
    nm = by.get("nmap")
    ctx = {"ssh_port": getattr(rem, "port", None) or 22}
    if opts.local:
        ctx["nmap"], ctx["why_no_nmap"] = None, "local mode"
    elif nm is None or nm.status != "ok":
        ctx["nmap"], ctx["why_no_nmap"] = None, "nmap not run"
    else:
        ctx["nmap"] = {p["port"] for p in nm.data.get("open_ports", [])}
    if "mysql" in by and str(by["mysql"].data.get("port", "")).isdigit():
        ctx["mysql_port"] = int(by["mysql"].data["port"])
    ctx["cve_now"] = by["cve"].data.get("now_detail", []) if "cve" in by else []
    return ctx


def assess(rem, opts: Options, out_dir: str, log=print) -> dict:
    ctx = Context(rem=rem, opts=opts)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    results, tool_log = [], []
    t_start = time.time()

    for name, fn in EXTERNAL:
        if name not in opts.skip:
            results.append(_run_scanner(name, fn, ctx, log))
            if name == "nmap":
                ctx.cache["nmap_open"] = results[-1].data.get("open_ports", [])
                ctx.cache["nmap_titles"] = [f.title for f in results[-1].findings]

    rem.progress = lambda msg: log("    " + msg)
    rem.connect()
    try:
        if rem.run("id -u", sudo=True).out.strip() != "0":
            raise PermissionError("Root privileges are required: a sudo user (with --ask-sudo-pass if sudo "
                                  "asks for a password) or root.")
        ctx.osinfo = detect(rem)
        ctx.cache["container"] = ctx.osinfo.container
        log(f"[i] Target: {ctx.osinfo.pretty} | kernel {ctx.osinfo.kernel}"
            + (" | inside a container" if ctx.osinfo.container else ""))

        portable = {}
        if opts.lynis_dir and "lynis" not in opts.skip:
            from .portable import available, check_dir
            if available(opts.lynis_dir):
                portable["lynis"] = check_dir(opts.lynis_dir)
        tm = ToolManager(rem, ctx.osinfo, keep=opts.keep_tools, skip=opts.skip, portable=portable)
        # Tools handled by the ToolManager: installed now and removed at the end (ClamAV, chkrootkit), or only
        # detected (rkhunter). Nothing to prepare if all their checks are skipped.
        managed = [t for t in ("clamav", "chkrootkit", "rkhunter") if t not in opts.skip]
        try:
            if managed:
                installed = [t for t in managed if t != "rkhunter"]
                log("[+] Preparation: " + (", ".join(installed) + " (installed now, removed at the end)"
                                           if installed else "checking whether rkhunter is present") + " ...")
                tm.prepare()
                ctx.tools_ok = tm.available
                ctx.cache["tool_installed"] = set(tm.installed)
            for name, fn in INTERNAL:
                if name not in opts.skip:
                    results.append(_run_scanner(name, fn, ctx, log))
        finally:
            if managed:
                log("[+] Cleanup: removing what was installed ...")
                tm.cleanup()
            tool_log = tm.log
    finally:
        rem.close()

    sources = ["native checks (accounts, sudo, SSH, permissions, services, kernel...)"]
    labels = {"nmap": "nmap + NSE scripts", "ssh_audit": "ssh-audit", "lynis": "Lynis (portable)",
              "cve": "CVE:", "clamav": "ClamAV"}
    for r in results:
        if r.name in labels and r.status == "ok":
            extra = r.data.get("lynis_version") or " + ".join(r.data.get("sources") or []) or ""
            sources.append(labels[r.name] + (f" {extra}" if extra else ""))
    meta = {"target": rem.host, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"), "os": ctx.osinfo.pretty, "kernel": ctx.osinfo.kernel,
            "container": ctx.osinfo.container, "version": __version__, "sources": sources,
            "mode": ("local, on the machine itself" if opts.local else
                     f"remote over SSH ({getattr(rem, 'user', '?')}@{rem.host}, auth "
                     f"{getattr(rem, 'auth_method', None) or '?'})"),
            "duration_s": int(time.time() - t_start)}
    rep = build_report(meta, results, tool_log, risk_context(results, opts, rem))
    md = to_markdown(rep)
    path = save(rep, md, out_dir, rem.host, ts, html=to_html(rep))
    rep["paths"] = {"dir": str(path), "html": str(path / "report.html"), "md": str(path / "report.md"),
                    "json": str(path / "report.json")}
    return rep


def recover(rem, confirm, log=print) -> bool:
    """Clean up the target after an interrupted run (see toolmgr.recover_interrupted)."""
    rem.progress = lambda msg: log("    " + msg)
    rem.connect()
    try:
        if rem.run("id -u", sudo=True).out.strip() != "0":
            raise PermissionError("Root privileges are required.")
        return recover_interrupted(rem, detect(rem), confirm, log)
    finally:
        rem.close()
