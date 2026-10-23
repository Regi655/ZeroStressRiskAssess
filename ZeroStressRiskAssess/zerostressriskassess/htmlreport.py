"""HTML report: the same analysis as report.md, designed to be READ (browser, print to PDF).

The risk table has many columns with long text; as Markdown in an editor or terminal the lines wrap
and become unreadable. In HTML the matrix is coloured, the table adapts to the window and the
evidence is expandable.

Security: all target-supplied text is passed through html.escape (a compromised target must not be
able to inject scripts or links), the page loads NOTHING from external sources and a
Content-Security-Policy forbids scripts, so the file can be opened safely offline.
"""
from __future__ import annotations

from html import escape

from . import cve, risk
from .models import SEVERITIES, clean_text

LEVEL_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
LV_CLASS = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low"}

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--muted:#5d6675;--line:#dde1e7;
--crit:#b42318;--crit-bg:#fde4e1;--high:#c4520c;--high-bg:#feead9;--med:#8a6a00;--med-bg:#fdf3c7;
--low:#2e7d32;--low-bg:#e3f2e4;--code:#eef0f3}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--card:#1d2128;--fg:#e6e8eb;--muted:#9aa3ae;--line:#323844;
--crit:#ff8a7a;--crit-bg:#4a1d19;--high:#ffb072;--high-bg:#4a2a12;--med:#f0cf5a;--med-bg:#3d3410;
--low:#8fd694;--low-bg:#1c3a1f;--code:#2a2f38}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Ubuntu,sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:1.6rem;margin:0 0 4px}h2{font-size:1.2rem;margin:32px 0 12px}
.muted{color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:12px 0}
.meta{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:0}
.meta dt{color:var(--muted)}.meta dd{margin:0}
.summary{display:flex;flex-wrap:wrap;gap:12px;align-items:stretch}
.overall{flex:1 1 220px;border-radius:10px;padding:16px;font-weight:600}
.overall .big{font-size:2rem;display:block}
.count{flex:0 1 120px;border-radius:10px;padding:12px;text-align:center}
.count b{display:block;font-size:1.8rem}
.crit{background:var(--crit-bg);color:var(--crit)}.high{background:var(--high-bg);color:var(--high)}
.med{background:var(--med-bg);color:var(--med)}.low{background:var(--low-bg);color:var(--low)}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:.8rem;font-weight:700;white-space:nowrap}
table{border-collapse:collapse;width:100%}
th,td{border-bottom:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}
th{font-size:.8rem;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)}
.scroll{overflow-x:auto}
.matrix{table-layout:fixed;min-width:560px}
.matrix td,.matrix th{text-align:center;vertical-align:middle;border:2px solid var(--card);border-radius:6px}
.matrix th:first-child{width:150px}
.matrix td{height:64px;min-width:90px}
.matrix td.empty{opacity:.35}
.matrix .n{font-size:1.4rem;font-weight:700;display:block}
.matrix .ids{font-size:.75rem}
.matrix th.row{text-align:right;white-space:nowrap}
.risk-n{font-size:1.3rem;font-weight:700}
.ip{white-space:nowrap;color:var(--muted);font-size:.85rem}
.fix{font-size:.9rem}
details summary{cursor:pointer;color:var(--muted);font-size:.85rem}
code{background:var(--code);padding:1px 4px;border-radius:4px;font-size:.85em;word-break:break-word}
ul.ev{margin:6px 0 0;padding-left:18px;font-size:.85rem}
.refs{font-size:.8rem;color:var(--muted)}
.st-skipped{color:var(--med)}.st-error{color:var(--crit)}
footer{margin-top:32px;font-size:.85rem;color:var(--muted)}
@media print{body{background:#fff}.card{break-inside:avoid}}
"""


def _e(text, limit=2000) -> str:
    return escape(clean_text(text, limit))


def _badge(level) -> str:
    return f'<span class="badge {LV_CLASS[level]}">{level}</span>'


def _matrix(rated) -> str:
    m = risk.matrix(rated)
    ids = {}
    for r in rated:
        ids.setdefault((r["impact"], r["probability"]), []).append(r["id"])
    h = ['<div class="scroll"><table class="matrix"><tr><th>Impact ↓ &nbsp; Likelihood →</th>']
    h += [f"<th>{p}<br>{escape(risk.PROBABILITY[p][0])}</th>" for p in range(1, 6)]
    h.append("</tr>")
    for i in range(5, 0, -1):
        h.append(f'<tr><th class="row">{i} {escape(risk.IMPACT[i][0])}</th>')
        for p in range(1, 6):
            lv, n = risk.level(i * p), m.get((i, p), 0)
            cls = LV_CLASS[lv] + ("" if n else " empty")
            body = (f'<span class="n">{n}</span><span class="ids">{", ".join(ids[(i, p)])}</span>' if n
                    else f'<span class="ids">{i * p}</span>')
            h.append(f'<td class="{cls}" title="risk {i * p}: {lv}">{body}</td>')
        h.append("</tr>")
    h.append("</table></div>")
    return "".join(h)


def _risk_rows(rep, rated) -> str:
    fx = {f["id"]: (sc["name"], f) for sc in rep["scans"] for f in sc["findings"]}
    out = []
    for r in rated:
        ev = []
        for fid in r["evidence"]:
            if fid in fx:
                name, f = fx[fid]
                det = f' — <code>{_e(f["detail"], 400)}</code>' if f.get("detail") else ""
                ev.append(f"<li><b>{fid}</b> [{escape(name)}, {escape(f['severity'])}] {_e(f['title'], 300)}{det}</li>")
        refs = r.get("refs") or {}
        ref = " · ".join(x for x in (("MITRE ATT&amp;CK " + ", ".join(map(escape, refs["mitre"]))) if refs.get("mitre") else "",
                                     ("CIS v8 " + ", ".join(map(escape, refs["cis"]))) if refs.get("cis") else "") if x)
        est = " (estimate)" if r.get("estimated") else ""
        out.append(
            f"<tr><td><b>{r['id']}</b></td>"
            f'<td><span class="risk-n">{r["risk"]}</span><br>{_badge(r["level"])}</td>'
            f"<td><b>{_e(r['title'], 300)}</b>"
            f'<div class="ip">Impact {r["impact"]} {escape(risk.IMPACT[r["impact"]][0])} × '
            f'Likelihood {r["probability"]} {escape(risk.PROBABILITY[r["probability"]][0])}{est}</div>'
            f'<div class="muted" style="font-size:.85rem">Rationale: {_e(r["probability_why"])}</div>'
            + (f'<div class="refs">{ref}</div>' if ref else "")
            + (f"<details><summary>Evidence ({len(ev)})</summary><ul class=\"ev\">{''.join(ev)}</ul></details>" if ev else "")
            + f'</td><td class="fix">{_e(r.get("fix") or "See the evidence.")}</td></tr>')
    return "".join(out)


def _cve(rep) -> str:
    sc = next((s for s in rep["scans"] if s["name"] == "cve" and s["data"].get("now_detail")), None)
    if not sc:
        return ""
    by = {}
    for v in sc["data"]["now_detail"]:
        by.setdefault(v["pkg"], []).append(v)
    sev = {s: i for i, s in enumerate(["critical", "high", "medium", "low"])}
    rows = []
    for pkg, vs in sorted(by.items(), key=lambda kv: (min(sev.get(v["severity"], 3) for v in kv[1]), -len(kv[1]))):
        worst = min((v["severity"] for v in vs), key=lambda x: sev.get(x, 3))
        kev = ", ".join(v["cve"] for v in vs if v.get("kev")) or "—"
        rows.append(f"<tr><td><code>{_e(pkg)}</code></td><td>{len(vs)}</td><td>{escape(worst)}</td>"
                    f"<td>{_e(kev)}</td><td><code>{_e(vs[0]['installed'])}</code> → <code>{_e(vs[0]['available'])}</code></td></tr>")
    return ("<h2>CVEs fixable now, by package</h2><div class=\"card scroll\"><p class=\"muted\">Sources: "
            f"{_e(cve.sources_text(sc['data']))}. Only CVEs whose update is already installable "
            "on the target. KEV = actively exploited (CISA catalogue).</p><table><tr><th>Package</th><th>CVEs</th>"
            "<th>Most severe</th><th>KEV</th><th>Installed → available</th></tr>" + "".join(rows) + "</table></div>")


def _method() -> str:
    imp = "".join(f"<tr><td><b>{i}</b> {escape(risk.IMPACT[i][0])}</td><td>{escape(risk.IMPACT[i][1])}</td></tr>"
                  for i in range(5, 0, -1))
    prob = "".join(f"<tr><td><b>{p}</b> {escape(risk.PROBABILITY[p][0])}</td><td>{escape(risk.PROBABILITY[p][1])}</td></tr>"
                   for p in range(5, 0, -1))
    return ("<h2>Method</h2><div class=\"card\"><p><b>Risk = Impact × Likelihood</b>, each from 1 to 5. "
            f"Levels: {_badge('CRITICAL')} 15–25 {_badge('HIGH')} 10–14 {_badge('MEDIUM')} 5–9 {_badge('LOW')} 1–4.</p>"
            "<div class=\"scroll\"><table><tr><th>Impact</th><th>Meaning</th></tr>" + imp + "</table></div>"
            "<div class=\"scroll\" style=\"margin-top:12px\"><table><tr><th>Likelihood</th><th>Meaning</th></tr>"
            + prob + "</table></div><ul><li>Likelihood starts from how the weakness is exploited and is adjusted "
            "with what the tool measured: a network weakness on a port that nmap cannot reach drops by 2; a CVE in "
            "the CISA KEV catalogue rises to 5.</li><li>Findings describing the same weakness form a single "
            "problem, with the others as evidence.</li><li>“(estimate)”: no specific rule, values derived "
            "from the finding severity.</li></ul></div>")


def _controls(rep) -> str:
    rows = []
    for sc in rep["scans"]:
        note = _e(sc["findings"][0]["title"], 200) if sc["status"] != "ok" and sc["findings"] else ""
        rows.append(f'<tr><td>{escape(sc["name"])}</td><td class="st-{escape(sc["status"])}">{escape(sc["status"])}</td>'
                    f'<td>{int(sc.get("duration", 0))} s</td><td>{len(sc["findings"])}</td><td>{note}</td></tr>')
    tools = "".join(f"<li><code>{_e(t['tool'] if t.get('package', '-') == '-' else t['package'], 300)}</code>: "
                    f"{_e(t['action'])}</li>" for t in rep.get("tools") or [])
    return ("<h2>Checks performed</h2><div class=\"card scroll\"><p class=\"muted\">A <i>skipped</i> or "
            "<i>error</i> check verified NOTHING: the reason is in the Notes column.</p><table><tr><th>Check</th>"
            "<th>Status</th><th>Duration</th><th>Findings</th><th>Notes</th></tr>" + "".join(rows) + "</table>"
            + (f"<p class=\"muted\">Tools installed and removed on the target:</p><ul>{tools}</ul>" if tools else "")
            + "</div>")


def _appendix(rep) -> str:
    order = {k: i for i, k in enumerate(SEVERITIES)}
    parts = []
    for sc in rep["scans"]:
        if not sc["findings"]:
            continue
        items = []
        for f in sorted(sc["findings"], key=lambda x: order[x["severity"]]):
            link = f" → <b>{escape(f['issue'])}</b>" if f.get("issue") else ""
            det = f' — <code>{_e(f["detail"], 600)}</code>' if f.get("detail") else ""
            items.append(f"<li><b>{f['id']}</b> [{escape(f['severity'])}] {_e(f['title'], 300)}{link}{det}</li>")
        parts.append(f"<details><summary><b>{escape(sc['name'])}</b> ({len(items)})</summary><ul class=\"ev\">"
                     + "".join(items) + "</ul></details>")
    return ("<h2>Appendix: findings of each check</h2><div class=\"card\">"
            + "".join(parts) + "</div>")


def _stage(rep) -> str:
    """Draft or final (meta stage) and, in the final version, the details omitted in review."""
    m, out = rep["meta"], ""
    if m.get("stage"):
        out += f'<div class="card"><b>{_e(m["stage"])}</b></div>'
    if rep.get("omissions"):
        items = "".join(f"<li><b>{_e(o['id'])}</b>" + (f" ({_e(o['problem'])})" if o.get("problem") else "")
                         + f" {_e(o['title'], 300)} - reason: {_e(o['reason'], 300)}</li>" for o in rep["omissions"])
        out += ('<h2>Details omitted in review</h2><div class="card"><p class="muted">These findings are still in '
                'the report with title and severity; their details (and the raw output of their check) were removed '
                f'before delivery, for the stated reason.</p><ul>{items}</ul></div>')
    return out


def to_html(rep: dict) -> str:
    m, s, rated = rep["meta"], rep["summary"], rep["risks"]
    lv = s["level"] if s["level"] in LV_CLASS else "LOW"
    counts = "".join(f'<div class="count {LV_CLASS[k]}"><b>{s["counts"][k]}</b>{k.lower()}</div>' for k in LEVEL_ORDER)
    meta = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in [
        ("Date", _e(m.get("timestamp", "?"))),
        ("System", _e(m.get("os", "?") + (f" (kernel {m['kernel']})" if m.get("kernel") else ""))
         + (f" — {_e(m['os_family'])}" if m.get("os_family") else "")
         + (" — <b>container</b>" if m.get("container") else "")),
        *([("Platform notes", _e(" ".join(m["os_notes"])))] if m.get("os_notes") else []),
        ("Mode", _e(m.get("mode", "?"))),
        *([("Scope", f"<b>{_e(m['scope'])}</b>")] if m.get("scope") else []),
        ("Sources", _e(", ".join(m.get("sources", [])))),
        ("Duration", f"{int(m.get('duration_s', 0)) // 60} min {int(m.get('duration_s', 0)) % 60} s"),
        ("Tool", f"ZeroStressRiskAssess {_e(m.get('version', '?'))}")])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Risk — {_e(m['target'], 200)}</title><style>{CSS}</style></head>
<body><main>
<h1>Risk assessment — {_e(m['target'], 200)}</h1>
<div class="card"><dl class="meta">{meta}</dl></div>
{_stage(rep)}
<div class="summary">
  <div class="overall {LV_CLASS[lv]}">Overall risk<span class="big">{lv}</span>
  <span style="font-weight:400">{len(rated)} problems; the most severe one counts</span></div>
  {counts}
</div>
<h2>Risk matrix (impact × likelihood)</h2>
<div class="card">{_matrix(rated)}<p class="muted">Each cell: how many problems and which ones (table IDs).
Empty cells show the risk value they would have.</p></div>
<h2>Risk table</h2>
<div class="card scroll"><table>
<tr><th>ID</th><th>Risk</th><th>Problem</th><th>Remediation</th></tr>
{_risk_rows(rep, rated)}
</table></div>
{_cve(rep)}
{_method()}
{_controls(rep)}
{_appendix(rep)}
<footer>The results are automatically collected indicators, not verdicts: every problem must be verified before
acting on it. The same data is available in report.md and report.json.</footer>
</main></body></html>
"""
