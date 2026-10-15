"""Report: 5x5 matrix and risk table (risk = impact x likelihood) in Markdown, HTML and JSON.

Build order (it matters):
  1. secrets in the findings are masked (redact.py) BEFORE anything else, because issue titles
     are derived from finding titles;
  2. findings -> issues (correlate.py: the same weakness seen by several checks is a single issue);
  3. issues -> impact, likelihood, risk (risk.py);
  4. Markdown: summary and matrix first, then the table, then method and details.
The Markdown uses ASCII-only graphics (x, ->, ...): Unicode arrows and dots are highlighted or shown
as boxes by some editors and terminals. report.html is the version intended for reading.
Target text is DATA, never formatting: _md() neutralises Markdown and HTML.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict
from pathlib import Path

from . import cve, risk
from .correlate import analyze
from .models import SEVERITIES, clean_text
from .redact import mask_report
from .validate import safe_name

RAW_LIMIT = 20000   # raw tool output can be very large: it is truncated in the JSON
LEVEL_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def build_report(meta: dict, results: list, tool_log: list, ctx: dict) -> dict:
    scans, n = [], 0
    for r in results:
        d = asdict(r)
        d["raw"] = clean_text(d["raw"], RAW_LIMIT)
        for f in d["findings"]:
            n += 1
            f["id"] = f"F{n:03d}"      # finding IDs, used to cite them as evidence
        scans.append(d)
    rep = {"meta": meta, "tools": tool_log, "scans": scans}
    mask_report(rep)
    issues = analyze(scans)
    rated = risk.assess(scans, issues, ctx)
    # IDs in table order (R01 = highest risk): easier to cite and read.
    new = {r["id"]: f"R{n:02d}" for n, r in enumerate(rated, 1)}
    for r in rated:
        r["id"] = new[r["id"]]
    for sc in scans:
        for f in sc["findings"]:
            if "issue" in f:
                f["issue"] = new.get(f["issue"])
                if not f["issue"]:
                    del f["issue"]
    counts = {lv: sum(1 for r in rated if r["level"] == lv) for lv in LEVEL_ORDER}
    rep["summary"] = {"level": risk.overall(rated), "counts": counts,
                      "matrix": {f"{i}x{p}": c for (i, p), c in risk.matrix(rated).items()},
                      "findings": {s: sum(1 for sc in scans for f in sc["findings"] if f["severity"] == s)
                                   for s in SEVERITIES}}
    rep["risks"] = rated
    return rep


# ---------------------------------------------------------------------- Markdown
def _md(text) -> str:
    """Neutralise Markdown/HTML in target-supplied text: a compromised target must not be able to inject
    links, images or formatting that would falsify the report.
    """
    t = clean_text(text, 2000).replace("`", "'").replace("\\", "/")
    for ch in "<>*_[]|":
        t = t.replace(ch, "\\" + ch)
    return t.replace("\n", " ")


def _code(text, limit) -> str:
    """Target text inside `code`: no backticks or newlines; overly long text is cut at a word boundary
    and marked with " [...]" (the full text remains in report.json).
    """
    s = clean_text(text, 2000).replace("`", "'").replace("\n", " ").replace("|", "/")
    if len(s) > limit:
        cut = s[:limit].rsplit(" ", 1)[0] if " " in s[:limit] else s[:limit]
        s = cut.rstrip(" ,;:") + " [...]"
    return s


def _table(headers, rows) -> list:
    """Markdown table with aligned columns (readable as plain text too); numbers right-aligned."""
    cols = [list(map(str, c)) for c in zip(headers, *rows)] if rows else [[h] for h in headers]
    w = [max(len(x) for x in c) for c in cols]
    num = [all(x.isdigit() for x in c[1:]) and len(c) > 1 for c in cols]
    line = lambda cells: "| " + " | ".join(c.rjust(n) if k else c.ljust(n)  # noqa: E731
                                           for c, n, k in zip(cells, w, num)) + " |"
    sep = "|" + "|".join("-" * (n + 1) + ":" if k else "-" * (n + 2) for n, k in zip(w, num)) + "|"
    return [line(headers), sep] + [line(list(map(str, r))) for r in rows]


def _matrix_md(rated: list) -> list:
    m = risk.matrix(rated)
    ids = {}
    for r in rated:
        ids.setdefault((r["impact"], r["probability"]), []).append(r["id"])
    head = ["Impact \\ Likelihood"] + [f"{p} {risk.PROBABILITY[p][0]}" for p in range(1, 6)]
    rows = []
    for i in range(5, 0, -1):
        cells = [f"**{i} {risk.IMPACT[i][0]}**"]
        for p in range(1, 6):
            lv = risk.level(i * p)
            n = m.get((i, p), 0)
            cells.append(f"**{n}** {lv}: {', '.join(ids[(i, p)][:4])}{' ...' if n > 4 else ''}" if n else "-")
        rows.append(cells)
    return _table(head, rows)


def to_markdown(rep: dict) -> str:
    m, s, rated = rep["meta"], rep["summary"], rep["risks"]
    L = [f"# Risk assessment — {_md(m['target'])}", ""]
    L += _table(["", ""], [
        ["Date", m.get("timestamp", "?")],
        ["System", f"{_md(m.get('os', '?'))} (kernel {_md(m.get('kernel', '?'))})"
                    + (" — **container**" if m.get("container") else "")],
        ["Mode", _md(m.get("mode", "?"))],
        ["Sources", _md(", ".join(m.get("sources", [])))],
        ["Tool", f"ZeroStressRiskAssess {_md(m.get('version', '?'))}"]])
    L += ["", f"## Overall risk: **{s['level']}**", "",
          f"{len(rated)} problems: " + ", ".join(f"{s['counts'][lv]} {lv.lower()}" for lv in LEVEL_ORDER)
          + ". The overall risk is that of the most severe problem.", ""]
    if m.get("stage"):
        L += [f"> **{_md(m['stage'])}**", ""]

    L += ["## Risk matrix (impact x likelihood)", "",
          "Each cell: number of problems, risk level, problem IDs (see the table). "
          "\"-\" = no problems.", ""]
    L += _matrix_md(rated) + [""]

    L += ["## Risk table", "",
          "Sorted by risk. *Rationale* explains the likelihood: where the weakness is exploited from and what "
          "the tool verified (e.g. whether the port is reachable from the controller).", ""]
    rows = []
    for r in rated:
        fix = r.get("fix") or ""
        rows.append([r["id"], f"{r['risk']} ({r['impact']}x{r['probability']})", r["level"], _md(r["title"]),
                     f"{r['impact']} {risk.IMPACT[r['impact']][0]}",
                     f"{r['probability']} {risk.PROBABILITY[r['probability']][0]}"
                     + (" (estimate)" if r.get("estimated") else ""),
                     _md(r["probability_why"]), _md(fix) or "see evidence"])
    L += _table(["ID", "Risk", "Level", "Problem", "Impact", "Likelihood", "Rationale", "Remediation"],
                rows) + ["", "The evidence for each problem is in the appendix (every finding points to its R..).", ""]

    cve = next((sc for sc in rep["scans"] if sc["name"] == "cve" and sc["data"].get("now_detail")), None)
    if cve:
        L += _cve_md(cve) + [""]

    L += _method_md() + [""]
    L += ["## Checks performed", "",
          "A *skipped* or *error* check verified NOTHING: the reason is in the Notes column.", ""]
    L += _table(["Check", "Status", "Duration (s)", "Findings", "Notes"],
                [[sc["name"], sc["status"], str(int(sc.get("duration", 0))), str(len(sc["findings"])),
                  _md(sc["findings"][0]["title"])[:110] if sc["status"] != "ok" and sc["findings"] else ""]
                 for sc in rep["scans"]]) + [""]
    if rep.get("tools"):
        L += ["Tools installed and removed on the target:", ""]
        L += [f"- `{_md(t.get('package', '-'))}`: {_md(t['action'])}" for t in rep["tools"]] + [""]

    L += ["## Appendix: findings of each check", "",
          "The evidence cited in the table. Finding severity: critical, high, medium, low, info.", ""]
    order = {k: i for i, k in enumerate(SEVERITIES)}
    for sc in rep["scans"]:
        if not sc["findings"]:
            continue
        L += [f"### {sc['name']}", ""]
        for f in sorted(sc["findings"], key=lambda x: order[x["severity"]]):
            det = f" - `{_code(f['detail'], 300)}`" if f.get("detail") else ""
            link = f" -> {f['issue']}" if f.get("issue") else ""
            L.append(f"- `{f['id']}` [{f['severity']}] {_md(f['title'])}{link}{det}")
        L.append("")
    L += ["---", "The results are automatically collected indicators, not verdicts: every problem must be verified "
          "before acting on it."]
    return "\n".join(L)


def _cve_md(sc: dict) -> list:
    by = {}
    for v in sc["data"]["now_detail"]:
        by.setdefault(v["pkg"], []).append(v)
    sev = {s: i for i, s in enumerate(["critical", "high", "medium", "low"])}
    rows = []
    for pkg, vs in sorted(by.items(), key=lambda kv: (min(sev.get(v["severity"], 3) for v in kv[1]), -len(kv[1])))[:30]:
        worst = min((v["severity"] for v in vs), key=lambda x: sev.get(x, 3))
        kev = [v["cve"] for v in vs if v.get("kev")]
        rows.append([_md(pkg), str(len(vs)), worst, _md(", ".join(kev)) or "—",
                     _md(f"{vs[0]['installed']} -> {vs[0]['available']}")])
    L = ["## CVEs fixable now, by package", "",
         f"Sources: {_md(cve.sources_text(sc['data']))}. Verified that the fixed "
         "version is ACTUALLY installable on the target. KEV = actively exploited (CISA catalogue).", ""]
    L += _table(["Package", "CVEs", "Most severe", "KEV", "Installed -> available"], rows)
    if len(by) > 30:
        L += ["", f"... and {len(by) - 30} more packages (full list in report.json)."]
    return L


def _method_md() -> list:
    L = ["## Method", "", "**Risk = Impact x Likelihood**, each from 1 to 5 (risk from 1 to 25).", ""]
    L += _table(["Impact", "Meaning"], [[f"{i} {risk.IMPACT[i][0]}", risk.IMPACT[i][1]] for i in range(5, 0, -1)])
    L += [""]
    L += _table(["Likelihood", "Meaning"],
                [[f"{p} {risk.PROBABILITY[p][0]}", risk.PROBABILITY[p][1]] for p in range(5, 0, -1)])
    L += ["", "Levels: **CRITICAL** 15-25, **HIGH** 10-14, **MEDIUM** 5-9, **LOW** 1-4.", "",
          "- Impact depends on the type of weakness (rules in `zerostressriskassess/risk.py`).",
          "- Likelihood starts from how the weakness is exploited (network, local account, interception, physical "
          "access) and is adjusted with what the tool measured: a network weakness on a port that nmap could NOT "
          "reach from the controller drops by 2; a CVE in the CISA KEV catalogue (actively exploited) rises to 5.",
          "- Findings describing the same weakness (e.g. anonymous FTP seen by nmap, by the configuration "
          "and by directory permissions) form a single problem, with the others as evidence.",
          "- \"(estimate)\": no specific rule, impact and likelihood derive from the finding severity."]
    return L


# ---------------------------------------------------------------------- output files
def save(rep: dict, md: str, base_dir: str, host: str, ts: str, html: str = "") -> Path:
    d = Path(base_dir) / f"{safe_name(host)}_{ts}"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)   # the report describes the machine's weaknesses: accessible to its author only
    js = json.dumps(rep, indent=2, ensure_ascii=False)
    write_private(d / "report.json", js)
    write_private(d / "report.md", md)
    if html:
        write_private(d / "report.html", html)
    # JSON fingerprint: the recipient can verify the report has not been modified
    # (sha256sum -c report.json.sha256).
    write_private(d / "report.json.sha256", hashlib.sha256(js.encode("utf-8")).hexdigest() + "  report.json\n")
    return d


def write_private(path, content: str):
    """Create the file ALREADY with mode 600 (write_text + chmod would leave a window in which it is readable)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(path, 0o600)
