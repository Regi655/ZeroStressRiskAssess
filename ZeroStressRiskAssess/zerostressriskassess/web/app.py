"""ZeroStressRiskAssess web interface (Streamlit). Started by `zsra-web`, never directly.

Same work as the console (console.py), from the browser: start assessments and follow them live, browse the
reports, compare two runs, check the external tools. Assessments run through the SAME code as the direct command
(cli.main, in a separate process: see jobs.py).

Access: the server listens on 127.0.0.1 only and every browser session must present the token printed by zsra-web
(as Jupyter does). Without it any local user could start assessments with this user's SSH keys.
"""
from __future__ import annotations

import argparse
import base64
import hmac
import os
import shlex
import shutil
import sys
from pathlib import Path

import streamlit as st

from zerostressriskassess import __version__, portal
from zerostressriskassess.compare import compare, to_markdown
from zerostressriskassess.console import list_reports, tools_status
from zerostressriskassess.risk import level as risk_level
from zerostressriskassess.scanners import ALL_NAMES
from zerostressriskassess.validate import valid_host
from zerostressriskassess.web import jobs

PAGES = ["New assessment", "Runs", "Reports", "Compare", "Tools"]
LEVEL_COLOUR = {"CRITICAL": "#c0392b", "HIGH": "#e67e22", "MEDIUM": "#f1c40f", "LOW": "#27ae60"}
MODES = {"Assessment over SSH": "scan", "External reconnaissance (no login)": "recon",
         "Recovery after an interrupted run": "recover"}


def _args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default=os.environ.get("ZSRA_WEB_OUT_DIR", "./reports"))
    a, _ = ap.parse_known_args(sys.argv[1:])
    return Path(a.out_dir).expanduser().resolve()


OUT_DIR = _args()


# ---------------------------------------------------------------------- access
def _check_access():
    if st.session_state.get("authorised"):
        return
    expected = os.environ.get("ZSRA_WEB_TOKEN", "")
    given = st.query_params.get("token", "")
    if expected and given and hmac.compare_digest(expected.encode(), given.encode()):
        st.session_state.authorised = True
        st.query_params.clear()   # the token leaves the address bar once the session is open
        return
    st.error("Access denied. Open the address printed by `zsra-web` in the terminal (it contains the access token).")
    st.stop()


# ---------------------------------------------------------------------- helpers
def _goto(page, **state):
    st.session_state.goto = page
    st.session_state.update(state)
    st.rerun()


def _badge(lv: str) -> str:
    return f":{ {'CRITICAL': 'red', 'HIGH': 'orange', 'MEDIUM': 'yellow', 'LOW': 'green'}.get(lv, 'gray') }[**{lv}**]"


def _report_label(row):
    path, rep = row
    m, s = rep.get("meta", {}), rep.get("summary", {})
    return f"{m.get('timestamp', '?')} · {m.get('target', '?')} · {s.get('level', '?')} · {len(rep.get('risks', []))} problems"


# ---------------------------------------------------------------------- new assessment
def page_new():
    st.header("New assessment")
    label = st.radio("Type", list(MODES), horizontal=True, key="mode_label")
    mode = MODES[label]
    last = st.session_state.setdefault("last_form", {})
    if mode == "recon":
        st.caption("Network probes from this machine only (nmap, ssh-audit, DNS, MySQL): no login, nothing installed, "
                   "run or written on the target.")
    elif mode == "recover":
        st.caption("Removes what an interrupted run left on the target. First a PREVIEW lists the packages: nothing "
                   "is removed until you confirm it on the Runs page.")
    else:
        st.caption("nmap and ssh-audit from here, then the internal checks over SSH. ClamAV, chkrootkit and "
                   "smartmontools are installed and removed at the end; Lynis is copied temporarily.")

    with st.form("assessment", clear_on_submit=True):   # clears the passwords; other fields keep `last` values
        c1, c2 = st.columns([3, 1])
        host = c1.text_input("Target (IP or hostname)", value=last.get("host", ""))
        port = c2.number_input("SSH port", 1, 65535, value=last.get("port", 22))
        user = key = ""
        secrets = {}
        hostkey = False
        if mode != "recon":
            c1, c2 = st.columns(2)
            user = c1.text_input("SSH user (root or a sudo user)", value=last.get("user", ""))
            key = c2.text_input("SSH private key (path)", value=last.get("key", ""), placeholder="~/.ssh/id_ed25519")
            c1, c2, c3 = st.columns(3)
            secrets["key"] = c1.text_input("Key passphrase", type="password")
            secrets["sudo"] = c2.text_input("sudo password", type="password")
            secrets["ssh"] = c3.text_input("SSH password (if no key)", type="password")
            hostkey = st.checkbox("Accept the host key if the target is not in known_hosts (first contact only!)")

        opts = {"accept_new_hostkey": hostkey}
        if mode != "recover":
            with st.expander("Options"):
                c1, c2 = st.columns(2)
                opts["nmap_ports"] = c1.text_input("nmap ports", value=last.get("nmap_ports", ""),
                                                   help="'1-1024,8080'; '-' = all; empty = top 1000")
                opts["nse"] = c2.selectbox("NSE scripts", ["default", "off", "tls"],
                                           format_func={"default": "default", "off": "off (ports and versions only)",
                                                        "tls": "default + TLS ciphers"}.get)
                if mode == "scan":
                    c1, c2, c3 = st.columns(3)
                    opts["clamav"] = c1.selectbox("ClamAV", ["default", "quick", "full"],
                                                  format_func={"default": "default", "quick": "quick (typical malware "
                                                               "locations)", "full": "whole disk (slow)"}.get)
                    opts["no_install"] = c2.checkbox("Install nothing on the target (--no-install)")
                    opts["keep_tools"] = c3.checkbox("Keep the installed tools (--keep-tools)")
                opts["skip"] = st.multiselect("Checks to skip", ALL_NAMES, default=last.get("skip", []))
                c1, c2 = st.columns(2)
                opts["dns_zones"] = c1.text_input("DNS zones to test for AXFR (space separated)",
                                                  value=last.get("dns_zones", ""))
                opts["scan_timeout"] = c2.number_input("Maximum minutes per check", 5, 600,
                                                       value=last.get("scan_timeout", 60))
            cfg = _portal_config()
            if cfg:
                opts["upload"] = st.checkbox(f"Upload the report to the portal at the end ({cfg.url})", value=cfg.auto)
            else:
                st.caption("Portal not configured: the report stays here (Tools › Portal to connect it).")
            authorised = st.checkbox("I have the system owner's authorisation for this assessment")
        else:
            authorised = True
        submitted = st.form_submit_button("Start", type="primary")

    if not submitted:
        return
    host = host.strip()
    st.session_state.last_form = {"host": host, "port": int(port), "user": user.strip(), "key": key.strip(),
                                  **{k: v for k, v in opts.items() if k in ("nmap_ports", "skip", "dns_zones",
                                                                              "scan_timeout")}}
    errors = []
    if not valid_host(host):
        errors.append("Invalid target: IP address or name (letters, digits, dots, hyphens).")
    if mode != "recon" and not user.strip():
        errors.append("An SSH user is required.")
    if key.strip() and not os.path.isfile(os.path.expanduser(key.strip())):
        errors.append(f"Key file not found: {key.strip()}")
    if secrets.get("key") and not key.strip():
        errors.append("A key passphrase was given without a key file.")
    if not authorised:
        errors.append("Confirm that you have the system owner's authorisation.")
    if errors:
        for e in errors:
            st.error(e)
        st.warning("Passwords were cleared: type them again.")
        return
    argv = jobs.build_argv(mode, host, user, port, key, opts)
    job = jobs.start(OUT_DIR, argv, secrets, kind="recover-preview" if mode == "recover" else mode,
                     confirm=mode != "recover")
    _goto("Runs", selected_job=job.id)


# ---------------------------------------------------------------------- runs
def page_runs():
    st.header("Runs")
    all_jobs = jobs.list_jobs(OUT_DIR)
    if not all_jobs:
        st.info("No runs yet: start one from **New assessment**.")
        return
    ids = [j.id for j in all_jobs]
    sel = st.session_state.get("selected_job")
    idx = ids.index(sel) if sel in ids else 0
    labels = {j.id: f"{j.info.get('started')} · {j.info.get('target')} · {j.info.get('kind')} · {j.status}"
              for j in all_jobs}
    jid = st.selectbox("Run", ids, index=idx, format_func=labels.get)
    st.session_state.selected_job = jid
    job = next(j for j in all_jobs if j.id == jid)
    st.code("zsra " + shlex.join(job.info.get("argv", [])), language="bash")

    st.fragment(run_every=2 if job.running else None)(_live)(jid)

    job = next(j for j in jobs.list_jobs(OUT_DIR) if j.id == jid)
    if job.running:
        return
    c1, c2 = st.columns([1, 4])
    if job.report_dir and c1.button("Open the report", type="primary"):
        _goto("Reports", selected_report=str(job.report_dir / "report.json"))
    if c2.button("Delete this run (log only, the report stays)"):
        shutil.rmtree(job.dir, ignore_errors=True)
        st.session_state.pop("selected_job", None)
        st.rerun()
    if job.waiting_confirmation:
        _confirm_recover(job)


def _live(jid):
    job = next((j for j in jobs.list_jobs(OUT_DIR) if j.id == jid), None)
    if job is None:
        return
    status = job.status
    was = st.session_state.get(f"status_{jid}")
    st.session_state[f"status_{jid}"] = status
    if was == "running" and status != "running":
        st.rerun(scope="app")   # finished: redraw the whole page (report button, confirmation)
    c1, c2 = st.columns([4, 1])
    c1.markdown(f"Status: **{status}** · started {job.info.get('started')}")
    if job.running and c2.button("Stop (Ctrl-C)", help="Interrupts the run; the cleanup on the target still runs"):
        if job.stop():
            st.toast("Interrupt sent: the run is cleaning up the target.")
    lines = job.log.splitlines()
    st.code("\n".join(lines[-500:]) or "(no output yet)", language=None)


def _confirm_recover(job):
    st.warning("The preview above lists the packages the interrupted run installed. Check the list: confirming "
               "removes them from the target.")
    with st.form("confirm_recover", clear_on_submit=True):
        c1, c2, c3 = st.columns(3)
        secrets = {"key": c1.text_input("Key passphrase", type="password"),
                   "sudo": c2.text_input("sudo password", type="password"),
                   "ssh": c3.text_input("SSH password (if no key)", type="password")}
        ok = st.form_submit_button("Remove the listed packages", type="primary")
    if ok:
        base = [a for a in job.info["argv"] if a not in ("--no-banner", "--yes")]
        if "--out-dir" in base:
            i = base.index("--out-dir")
            del base[i:i + 2]
        new = jobs.start(OUT_DIR, base, secrets, kind="recover", confirm=True)
        _goto("Runs", selected_job=new.id)


# ---------------------------------------------------------------------- reports
def page_reports():
    st.header("Reports")
    rows = list_reports(OUT_DIR)
    if not rows:
        st.info(f"No reports in {OUT_DIR}.")
        return
    paths = [str(p) for p, _ in rows]
    sel = st.session_state.get("selected_report")
    choice = st.selectbox("Report", range(len(rows)), index=paths.index(sel) if sel in paths else 0,
                          format_func=lambda i: _report_label(rows[i]))
    st.session_state.selected_report = paths[choice]
    path, rep = rows[choice]
    meta, summ = rep.get("meta", {}), rep.get("summary", {})

    st.caption(f"{meta.get('os', '?')} · kernel {meta.get('kernel', '?')} · {meta.get('mode', '')} · "
               f"{int(meta.get('duration_s', 0)) // 60} min · zsra {meta.get('version', '?')}")
    if meta.get("stage"):
        st.warning(meta["stage"])
    cols = st.columns(5)
    cols[0].markdown(f"Overall risk  \n{_badge(summ.get('level', '?'))}")
    for c, lv in zip(cols[1:], ["CRITICAL", "HIGH", "MEDIUM", "LOW"]):
        c.metric(lv.capitalize(), summ.get("counts", {}).get(lv, 0))

    t_risks, t_matrix, t_findings, t_html, t_tools, t_files = st.tabs(
        ["Risks", "Matrix", "Findings", "Full report", "Tools on the target", "Files"])
    with t_risks:
        _risks(rep)
    with t_matrix:
        _matrix(summ.get("matrix", {}))
    with t_findings:
        _findings(rep)
    with t_html:
        html = path.parent / "report.html"
        if html.exists():
            # As a data: URL the frame gets an opaque origin: even a report altered after the fact could not
            # reach the app (an HTML string or a Path would be embedded same-origin, with script access).
            src = "data:text/html;base64," + base64.b64encode(html.read_bytes()).decode("ascii")
            st.iframe(src, height=1100)
        else:
            st.info("No report.html in this folder.")
    with t_tools:
        st.dataframe([{k: t.get(k, "") for k in ("tool", "package", "action", "frm", "to", "detail")}
                      for t in rep.get("tools", [])], width="stretch", hide_index=True)
    with t_files:
        st.caption(f"Folder: `{path.parent}`. A plaintext draft: deliver it with `finalize` (encrypted and signed).")
        cfg = _portal_config()
        if cfg and st.button(f"Upload to the portal ({cfg.url})", key="portal_upload"):
            try:
                ok, line = portal.describe(portal.upload(cfg, path), cfg)
            except portal.PortalError as exc:
                ok, line = False, str(exc)
            (st.success if ok else st.error)(line)
        for name, mime in (("report.html", "text/html"), ("report.pdf", "application/pdf"),
                           ("report.md", "text/markdown"), ("report.json", "application/json"),
                           ("report.json.sha256", "text/plain")):
            f = path.parent / name
            if f.exists():
                st.download_button(name, f.read_bytes(), file_name=f"{path.parent.name}_{name}", mime=mime,
                                   key=f"dl_{name}")


def _risks(rep):
    risks = rep.get("risks", [])
    if not risks:
        st.success("No problems in the risk table.")
        return
    c1, c2 = st.columns([2, 3])
    levels = c1.multiselect("Levels", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    q = c2.text_input("Search", placeholder="title, check, fix...").lower()
    shown = [r for r in risks if r.get("level") in levels
             and (not q or q in (r.get("title", "") + " ".join(r.get("scans", [])) + r.get("fix", "")).lower())]
    st.dataframe([{"ID": r["id"], "Level": r["level"], "Risk": r["risk"], "Impact": r["impact"],
                   "Likelihood": r["probability"], "Problem": r["title"], "Checks": ", ".join(r.get("scans", [])),
                   "Exposed": "yes" if r.get("exposed") else ""} for r in shown],
                 width="stretch", hide_index=True,
                 column_config={"Risk": st.column_config.ProgressColumn("Risk", min_value=0, max_value=25, format="%d")})
    if not shown:
        return
    rid = st.selectbox("Details", [r["id"] for r in shown],
                       format_func=lambda i: next(f"{r['id']} – {r['title']}" for r in shown if r["id"] == i))
    r = next(r for r in shown if r["id"] == rid)
    findings = {f["id"]: f for s in rep.get("scans", []) for f in s.get("findings", [])}
    st.markdown(f"#### {r['id']} · {_badge(r['level'])} · risk {r['risk']} = {r['impact']} × {r['probability']}"
                + (" (estimated)" if r.get("estimated") else ""))
    st.markdown(f"**{r['title']}**")
    st.markdown(f"- **Impact {r['impact']}**: {r.get('impact_why', '')}\n"
                f"- **Likelihood {r['probability']}**: {r.get('probability_why', '')}")
    st.markdown(f"**What to do:** {r.get('fix', '')}")
    refs = r.get("refs", {})
    if refs.get("mitre") or refs.get("cis"):
        st.caption(f"MITRE ATT&CK: {', '.join(refs.get('mitre', [])) or '-'} · CIS: {', '.join(refs.get('cis', [])) or '-'}")
    ev = [findings[e] for e in r.get("evidence", []) if e in findings]
    if ev:
        st.markdown("**Evidence**")
        for f in ev:
            with st.expander(f"{f['id']} · {f.get('severity', '')} · {f.get('title', '')}"):
                st.text(f.get("detail") or "(no detail)")


def _matrix(matrix):
    cells = []
    for imp in range(5, 0, -1):
        tds = [f"<th>{imp}</th>"]
        for lik in range(1, 6):
            n = matrix.get(f"{imp}x{lik}", 0)
            colour = LEVEL_COLOUR[risk_level(imp * lik)]
            style = f"background:{colour};opacity:{1 if n else 0.25};color:#000;font-weight:{700 if n else 400}"
            tds.append(f'<td style="{style}">{n or ""}</td>')
        cells.append("<tr>" + "".join(tds) + "</tr>")
    head = "<tr><th></th>" + "".join(f"<th>{i}</th>" for i in range(1, 6)) + "</tr>"
    st.markdown(
        "<style>.zm td,.zm th{width:3.2em;height:2.6em;text-align:center;border:1px solid #8884}</style>"
        f'<table class="zm"><caption>Impact (rows) × likelihood (columns): number of problems</caption>'
        f"{''.join(cells)}{head}</table>", unsafe_allow_html=True)   # only integers and fixed colours: no report text
    st.caption("Levels: CRITICAL 15-25, HIGH 10-14, MEDIUM 5-9, LOW 1-4.")


def _findings(rep):
    sev = ["critical", "high", "medium", "low", "info"]
    chosen = st.multiselect("Severity", sev, default=sev[:4])
    rows = [{"ID": f["id"], "Severity": f.get("severity", ""), "Check": s.get("name", ""), "Finding": f.get("title", ""),
             "Detail": (f.get("detail") or "")[:300]}
            for s in rep.get("scans", []) for f in s.get("findings", []) if f.get("severity") in chosen]
    st.dataframe(rows, width="stretch", hide_index=True)
    st.markdown("**Checks**")
    st.dataframe([{"Check": s.get("name"), "Status": s.get("status"), "Findings": len(s.get("findings", [])),
                   "Seconds": round(s.get("duration") or 0)} for s in rep.get("scans", [])],
                 width="stretch", hide_index=True)


# ---------------------------------------------------------------------- compare
def page_compare():
    st.header("Compare two runs")
    rows = list_reports(OUT_DIR)
    by_target = {}
    for row in rows:
        by_target.setdefault(str(row[1].get("meta", {}).get("target", "?")), []).append(row)
    targets = [t for t, r in by_target.items() if len(r) >= 2]
    if not targets:
        st.info("At least two reports of the same target are needed.")
        return
    target = st.selectbox("Target", targets)
    runs = by_target[target]
    c1, c2 = st.columns(2)
    i_old = c1.selectbox("Before", range(len(runs)), index=1, format_func=lambda i: _report_label(runs[i]))
    i_new = c2.selectbox("After", range(len(runs)), index=0, format_func=lambda i: _report_label(runs[i]))
    if i_old == i_new:
        st.warning("Choose two different runs.")
        return
    old, new = runs[i_old][1], runs[i_new][1]
    if str(old["meta"].get("timestamp", "")) > str(new["meta"].get("timestamp", "")):
        st.warning("“Before” is LATER than “After”: order probably reversed.")
    md = to_markdown(old, new, compare(old, new))
    st.download_button("Download as Markdown", md.encode("utf-8"), file_name=f"compare_{target}.md", mime="text/markdown")
    st.markdown(md)   # no unsafe_allow_html: any HTML in the report text is shown as text


# ---------------------------------------------------------------------- tools
def page_tools():
    st.header("Tools on this machine")
    st.dataframe([{"Tool": n, "Status": "ok" if ok else "missing", "Path / how to install": w}
                  for n, ok, w in tools_status()], width="stretch", hide_index=True)
    st.caption("Missing tools are skipped and reported as such.")
    st.caption(f"Reports folder: `{OUT_DIR}`")
    _portal_settings()


def _portal_config():
    try:
        return portal.load_config()
    except portal.PortalError as exc:
        st.warning(f"Portal: {exc}")
        return None


def _portal_settings():
    st.subheader("Portal (ZeroStressRiskAssessWeb)")
    st.caption("The private portal of the suite keeps the reports of every machine and compares them over time. "
               "It needs an API token: in the portal, Account › API tokens (a token can only upload reports).")
    cfg = _portal_config()
    if cfg:
        st.markdown(f"Connected to **{cfg.url}** · token `{cfg.masked}` · "
                    f"{'upload after every assessment' if cfg.auto else 'upload only when asked'} · from `{cfg.source}`")
        c1, c2 = st.columns([1, 4])
        if c1.button("Check the token"):
            try:
                a = portal.check(cfg)
                (st.success if portal.token_ok(a) else st.error)(
                    "Token accepted." if portal.token_ok(a) else portal.describe(a, cfg)[1])
            except portal.PortalError as exc:
                st.error(str(exc))
        if cfg.source == str(portal.config_path()) and c2.button("Disconnect (delete the saved token)"):
            portal.config_path().unlink(missing_ok=True)
            st.rerun()
    with st.form("portal_login", clear_on_submit=True):
        c1, c2 = st.columns(2)
        url = c1.text_input("Portal address", value=cfg.url if cfg else "", placeholder="https://zsra.example.org")
        token = c2.text_input("API token", type="password", placeholder="zsra_...")
        c1, c2 = st.columns(2)
        ca = c1.text_input("CA file (portal with its own authority)", value=cfg.ca_file if cfg else "",
                           placeholder="~/zsra-root.crt")
        auto = c2.checkbox("Upload after every assessment", value=cfg.auto if cfg else True)
        if st.form_submit_button("Connect" if not cfg else "Connect again"):
            try:
                new = portal.Config(portal.check_url(url), token.strip(), ca.strip(), auto)
                if not new.token:
                    raise portal.PortalError("the API token is empty")
                a = portal.check(new)
                if not portal.token_ok(a):
                    raise portal.PortalError(portal.describe(a, new)[1])
                st.success(f"Token accepted: saved in {portal.save_config(new)} (mode 600).")
            except portal.PortalError as exc:
                st.error(f"{exc}: not saved.")


# ---------------------------------------------------------------------- main
def main():
    st.set_page_config(page_title="ZeroStressRiskAssess", page_icon="🛡️", layout="wide")
    _check_access()
    if "goto" in st.session_state:   # set before the sidebar radio exists: the only moment it may change
        st.session_state.page = st.session_state.pop("goto")
    with st.sidebar:
        st.title("ZeroStressRiskAssess")
        st.caption(f"version {__version__}")
        page = st.radio("Section", PAGES, key="page", label_visibility="collapsed")
        running = sum(j.running for j in jobs.list_jobs(OUT_DIR))
        if running:
            st.info(f"{running} run(s) in progress")
        st.caption("Never type passwords anywhere but the password fields: they go to the run's memory only.")
    {"New assessment": page_new, "Runs": page_runs, "Reports": page_reports, "Compare": page_compare,
     "Tools": page_tools}[page]()


if __name__ == "__main__":   # `streamlit run` executes the file as __main__; a plain import (tests) draws nothing
    main()
