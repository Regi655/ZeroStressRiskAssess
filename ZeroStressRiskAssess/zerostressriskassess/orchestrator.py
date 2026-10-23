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

import re
import time
from datetime import datetime

from . import __version__
from .models import Context, Options, ScanResult
from .osinfo import FAMILY_NAMES, detect
from .htmlreport import to_html
from .report import DRAFT_STAGE, build_report, save, to_markdown
from .scanners import EXTERNAL, INTERNAL
from .toolmgr import DETECT_ONLY, HOST_ONLY_TOOLS, TOOL_SCAN, TOOLS, ToolManager, recover_interrupted


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


def risk_context(results, opts: Options, rem, family: str = "debian") -> dict:
    """What the risk model needs to know about what the tool actually MEASURED (and the target's family, for
    the commands in the remediation texts)."""
    by = {r.name: r for r in results}
    nm = by.get("nmap")
    ctx = {"ssh_port": getattr(rem, "port", None) or 22, "family": family}
    if opts.local:
        ctx["nmap"], ctx["why_no_nmap"] = None, "local mode"
    elif nm is None or nm.status != "ok":
        ctx["nmap"], ctx["why_no_nmap"] = None, "nmap not run"
    else:
        ctx["nmap"] = {p["port"] for p in nm.data.get("open_ports", [])}
    if "mysql" in by and str(by["mysql"].data.get("port", "")).isdigit():
        ctx["mysql_port"] = int(by["mysql"].data["port"])
    ctx["cve_now"] = by["cve"].data.get("now_detail", []) if "cve" in by else []
    ctx["security_named"] = by["updates"].data.get("security_named", []) if "updates" in by else []
    return ctx


def recon(target, opts: Options, out_dir: str, log=print) -> dict:
    """External reconnaissance only: nmap + NSE, ssh-audit, DNS and MySQL probes from the controller.

    `target` is a NoLogin object: no login, nothing installed, copied, run or written on the target. The report
    says so, because a short list of problems here does NOT mean the machine is secure: accounts, configuration,
    packages, malware and rootkits were not examined.
    """
    from .scanners.recon import RECON, guess_os
    ctx = Context(rem=target, opts=opts)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    results, t_start = [], time.time()
    log(f"[i] External reconnaissance of {target.host}: no login, nothing run or written on the target")
    for name, fn in EXTERNAL + RECON:
        if name not in opts.skip:
            results.append(_run_scanner(name, fn, ctx, log))
            if name == "nmap":
                ctx.cache["nmap_open"] = results[-1].data.get("open_ports", [])
                ctx.cache["nmap_titles"] = [f.title for f in results[-1].findings]
    banners = [str(p.get("service", "")) for p in ctx.cache.get("nmap_open", [])]
    banners += [f.title for r in results if r.name == "ssh_audit" for f in r.findings]
    g = guess_os(banners)
    sources = [lbl for name, lbl in (("nmap", "nmap + NSE scripts"), ("ssh_audit", "ssh-audit"),
                                     ("dns", "DNS probes"), ("mysql", "MySQL probe"))
               if any(r.name == name and r.status == "ok" for r in results)]
    meta = {"target": target.host, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "os": (f"{g['label']} (guessed from service banners, not verified)" if g["label"]
                   else "not determined (no login: only service banners are available)"),
            "kernel": "", "version": __version__, "sources": sources,
            "mode": "external reconnaissance only: no login, nothing run or written on the target",
            "scope": ("Only what is visible from the network was examined. Accounts, sudo, configuration, packages, "
                      "updates, malware and rootkits were NOT checked: a short list of problems does not mean the "
                      "machine is secure."),
            "duration_s": int(time.time() - t_start), "stage": DRAFT_STAGE}
    if g["evidence"]:
        meta["os_notes"] = [f"Distribution hint from the banner: {g['evidence']}"]
    family = g["family"] if g["family"] in ("debian", "rhel") else "debian"
    rctx = risk_context(results, opts, target, family)
    rctx["why_no_nmap"] = rctx.get("why_no_nmap", "nmap not run")
    rep = build_report(meta, results, [], rctx)
    md = to_markdown(rep)
    pdf = _pdf(rep, log)
    path = save(rep, md, out_dir, target.host, ts, html=to_html(rep), pdf=pdf)
    rep["paths"] = {"dir": str(path), "html": str(path / "report.html"), "md": str(path / "report.md"),
                    "json": str(path / "report.json")}
    if pdf:
        rep["paths"]["pdf"] = str(path / "report.pdf")
    return rep


def _require_root(rem) -> None:
    """Root via sudo (or root itself), with a message that says WHAT went wrong."""
    r = rem.run("id -u", sudo=True, timeout=60)
    if r.out.strip().splitlines()[-1:] == ["0"]:
        return
    if re.search(r"try again|incorrect password", r.out, re.I):
        raise PermissionError("sudo REJECTED the password given with --ask-sudo-pass / --sudo-pass-env "
                              f"(user {getattr(rem, 'user', '?')}): check it and retry.")
    if re.search(r"password is required|a terminal is required", r.out, re.I):
        raise PermissionError("sudo asks for a password, so add --ask-sudo-pass (or --sudo-pass-env).")
    raise PermissionError("Root privileges are required: a sudo user (with --ask-sudo-pass if sudo asks for a "
                          "password) or root." + (f" sudo said: {r.out.strip()[:160]}" if r.out.strip() else ""))


def _pdf(rep, log) -> bytes:
    """report.pdf when ReportLab is installed (optional). A PDF failure never costs the other formats."""
    from . import pdfreport
    if not pdfreport.available():
        return b""
    try:
        return pdfreport.pdf_bytes(rep)
    except Exception as exc:   # noqa: BLE001 - the report on disk matters more than its PDF copy
        log(f"[!] PDF not written ({type(exc).__name__}: {exc}); the HTML, Markdown and JSON reports are complete")
        return b""


def assess(rem, opts: Options, out_dir: str, log=print) -> dict:
    ctx = Context(rem=rem, opts=opts)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    results, tool_log = [], []
    t_start = time.time()

    # --local: nmap and ssh-audit are NOT run (README, section 5). From the machine itself they would scan it through
    # the loopback, with no firewall in between: every listening service would look "reachable" (seen on the
    # Ubuntu 26.04 laptop, 2026-10-22: MySQL on 3306 rated as exposed although iptables has INPUT DROP).
    if opts.local:
        log("[i] Local mode: nmap and ssh-audit not run (from inside they would bypass the firewall); "
            "network exposure is not verified, use --recon-only from another machine for that")
    for name, fn in EXTERNAL:
        if name not in opts.skip and not opts.local:
            results.append(_run_scanner(name, fn, ctx, log))
            if name == "nmap":
                ctx.cache["nmap_open"] = results[-1].data.get("open_ports", [])
                ctx.cache["nmap_titles"] = [f.title for f in results[-1].findings]

    rem.progress = lambda msg: log("    " + msg)
    rem.connect()
    try:
        _require_root(rem)
        ctx.osinfo = detect(rem)
        ctx.cache["container"] = ctx.osinfo.container
        log(f"[i] Target: {ctx.osinfo.pretty} | {FAMILY_NAMES[ctx.osinfo.family]} family, {ctx.osinfo.pkg_mgr} | "
            f"kernel {ctx.osinfo.kernel}" + (" | inside a container" if ctx.osinfo.container else ""))
        for note in ctx.osinfo.notes:
            log(f"[!] {note}")

        portable = {}
        if opts.lynis_dir and "lynis" not in opts.skip:
            from .portable import available, check_dir
            if available(opts.lynis_dir):
                portable["lynis"] = check_dir(opts.lynis_dir)
        tm = ToolManager(rem, ctx.osinfo, keep=opts.keep_tools, skip=opts.skip, portable=portable,
                         no_install=opts.no_install)
        # Tools handled by the ToolManager: installed now and removed at the end (ClamAV, chkrootkit,
        # smartmontools), or only detected (rkhunter). Nothing to prepare if all their checks are skipped.
        managed = [t for t in (*TOOLS, *DETECT_ONLY) if TOOL_SCAN.get(t, t) not in opts.skip
                   and not (t in HOST_ONLY_TOOLS and ctx.osinfo.container)]
        try:
            if managed:
                installed = [t for t in managed if t != "rkhunter"]
                if opts.no_install:
                    log("[+] Preparation: --no-install, nothing is installed: checking which tools are already "
                        "present ...")
                else:
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
                log("[+] Cleanup: nothing was installed (--no-install)" if opts.no_install
                    else "[+] Cleanup: removing what was installed ...")
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
            "os_family": f"{FAMILY_NAMES[ctx.osinfo.family]} family, {ctx.osinfo.pkg_mgr}", "os_notes": ctx.osinfo.notes,
            "container": ctx.osinfo.container, "version": __version__, "sources": sources,
            "mode": ("local, on the machine itself" if opts.local else
                     f"remote over SSH ({getattr(rem, 'user', '?')}@{rem.host}, auth "
                     f"{getattr(rem, 'auth_method', None) or '?'})")
                    + ("; --no-install: nothing installed on the target" if opts.no_install else ""),
            "duration_s": int(time.time() - t_start), "stage": DRAFT_STAGE}
    rep = build_report(meta, results, tool_log, risk_context(results, opts, rem, ctx.osinfo.family))
    md = to_markdown(rep)
    pdf = _pdf(rep, log)
    path = save(rep, md, out_dir, rem.host, ts, html=to_html(rep), pdf=pdf)
    rep["paths"] = {"dir": str(path), "html": str(path / "report.html"), "md": str(path / "report.md"),
                    "json": str(path / "report.json")}
    if pdf:
        rep["paths"]["pdf"] = str(path / "report.pdf")
    return rep


def recover(rem, confirm, log=print) -> bool:
    """Clean up the target after an interrupted run (see toolmgr.recover_interrupted)."""
    rem.progress = lambda msg: log("    " + msg)
    rem.connect()
    try:
        _require_root(rem)
        return recover_interrupted(rem, detect(rem), confirm, log)
    finally:
        rem.close()
