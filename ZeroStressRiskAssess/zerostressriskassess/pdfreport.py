"""PDF version of the report (report.pdf), built with ReportLab from the same data as the HTML.

WHY a PDF of its own and not "print the HTML": a PDF is what gets attached to an e-mail, archived or handed to
someone who will not open an HTML file; printing from the browser depends on the browser and loses the colours or
cuts the tables. ReportLab writes the PDF directly from report.json: same result on every machine, no browser.

ReportLab is an OPTIONAL dependency (`pip install reportlab`, done by setup.sh): without it the other formats are
written as usual and the terminal says how to get the PDF. `zsra-pdf REPORT_DIR` produces it for an existing report.

Target text is DATA: it is escaped before reaching ReportLab's markup (a "<" in a file name would otherwise break
the paragraph, or inject formatting). Characters the font cannot draw are replaced, never silently dropped.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from xml.sax.saxutils import escape

from . import risk
from .models import SEVERITIES, clean_text
from .report import LEVEL_ORDER

# The same palette as the HTML report.
COLOURS = {"CRITICAL": ("#b42318", "#fde4e1"), "HIGH": ("#c4520c", "#feead9"), "MEDIUM": ("#8a6a00", "#fdf3c7"),
           "LOW": ("#2e7d32", "#e3f2e4")}
# DejaVu Sans draws almost every character (arrows, accents, box symbols in banners); Helvetica only Latin-1.
FONT_CANDIDATES = ["/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",          # Debian, Ubuntu
                   "/usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf",        # Fedora, RHEL
                   "/usr/share/fonts/TTF/DejaVuSans.ttf",                      # Arch
                   "/usr/share/fonts/dejavu/DejaVuSans.ttf"]


def available() -> bool:
    import importlib.util
    return importlib.util.find_spec("reportlab") is not None


def _fonts():
    """(regular, bold, unicode?) font names: DejaVu if present on the system, otherwise Helvetica."""
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    for path in FONT_CANDIDATES:
        bold = path.replace("DejaVuSans.ttf", "DejaVuSans-Bold.ttf")
        if Path(path).is_file() and Path(bold).is_file():
            try:
                pdfmetrics.registerFont(TTFont("ZsraSans", path))
                pdfmetrics.registerFont(TTFont("ZsraSans-Bold", bold))
                pdfmetrics.registerFontFamily("ZsraSans", normal="ZsraSans", bold="ZsraSans-Bold")
                return "ZsraSans", "ZsraSans-Bold", True
            except Exception:   # a damaged font file must not cost the report
                pass
    return "Helvetica", "Helvetica-Bold", False


def to_pdf(rep: dict, path) -> None:
    """Write the report as a PDF (A4 landscape: the risk table has many columns)."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    regular, bold, uni = _fonts()

    def t(text, limit=2000) -> str:
        """Target text -> safe markup."""
        s = clean_text(str(text if text is not None else ""), limit)
        if not uni:
            s = s.encode("latin-1", "replace").decode("latin-1")
        return escape(s)

    base = ParagraphStyle("b", fontName=regular, fontSize=8.5, leading=11, alignment=TA_LEFT)
    small = ParagraphStyle("s", parent=base, fontSize=7.5, leading=9.5)
    muted = ParagraphStyle("m", parent=small, textColor=colors.HexColor("#5d6675"))
    h1 = ParagraphStyle("h1", parent=base, fontName=bold, fontSize=17, leading=21, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=base, fontName=bold, fontSize=12, leading=15, spaceBefore=10, spaceAfter=5,
                        textColor=colors.HexColor("#1f3a5f"))
    P = Paragraph
    m, s, rated = rep["meta"], rep["summary"], rep["risks"]
    grid = [("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dde1e7")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTNAME", (0, 0), (-1, -1), regular), ("FONTSIZE", (0, 0), (-1, -1), 8)]
    head = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f3a5f")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), bold)]

    def table(rows, widths, extra=()):
        tb = Table(rows, colWidths=widths, repeatRows=1)
        tb.setStyle(TableStyle(grid + head + list(extra)))
        return tb

    def level_cell(lv):
        fg, _ = COLOURS.get(lv, ("#1d2330", "#ffffff"))
        return P(f'<font color="{fg}"><b>{lv}</b></font>', base)

    story = [P(f"Risk assessment — {t(m.get('target', '?'))}", h1)]
    system = (t(m.get("os", "?")) + (f" (kernel {t(m['kernel'])})" if m.get("kernel") else "")
              + (f" — {t(m['os_family'])}" if m.get("os_family") else "") + (" — <b>container</b>" if m.get("container") else ""))
    meta = [["Date", t(m.get("timestamp", "?"))], ["System", system]]
    if m.get("os_notes"):
        meta.append(["Platform notes", t(" ".join(m["os_notes"]))])
    meta.append(["Mode", t(m.get("mode", "?"))])
    if m.get("scope"):
        meta.append(["Scope", f"<b>{t(m['scope'])}</b>"])
    meta += [["Sources", t(", ".join(m.get("sources", [])))], ["Tool", f"ZeroStressRiskAssess {t(m.get('version', '?'))}"]]
    mt = Table([[P(f"<b>{k}</b>", base), P(v, base)] for k, v in meta], colWidths=[32 * mm, 230 * mm])
    mt.setStyle(TableStyle(grid))
    story += [mt, Spacer(1, 4)]
    if m.get("stage"):
        story.append(P(f"<b>{t(m['stage'])}</b>", ParagraphStyle("st", parent=base, textColor=colors.HexColor("#b42318"))))

    lv = s["level"]
    fg, bg = COLOURS.get(lv, COLOURS["LOW"])
    counts = " · ".join(f"{s['counts'].get(x, 0)} {x.lower()}" for x in LEVEL_ORDER)
    big = ParagraphStyle("big", parent=base, leading=22)   # the 18 pt level under the 9 pt label must not overlap
    ov = Table([[P(f'<font size="9">Overall risk</font><br/><font size="18" color="{fg}"><b>{lv}</b></font>', big),
                 P(f"{len(rated)} problems: {counts}. The overall risk is that of the most severe problem.", base)]],
               colWidths=[45 * mm, 217 * mm])
    ov.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), colors.HexColor(bg)), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                            ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#dde1e7"))]))
    story += [Spacer(1, 6), ov]

    if rep.get("omissions"):
        story.append(P("Details omitted in review", h2))
        story.append(P("These findings are still in the report with title and severity; their details (and the raw "
                       "output of their check) were removed before delivery, for the stated reason.", muted))
        for o in rep["omissions"]:
            story.append(P(f"<b>{t(o['id'])}</b>" + (f" ({t(o['problem'])})" if o.get("problem") else "")
                           + f" {t(o['title'], 300)} — reason: {t(o['reason'], 300)}", base))

    # --- matrix: impact rows 5..1, likelihood columns 1..5, each cell coloured by the level of its value.
    mx = risk.matrix(rated)
    ids = {}
    for r in rated:
        ids.setdefault((r["impact"], r["probability"]), []).append(r["id"])
    rows = [[P("<b>Impact \\ Likelihood</b>", small)] + [P(f"<b>{p} {risk.PROBABILITY[p][0]}</b>", small) for p in range(1, 6)]]
    style = []
    for ri, i in enumerate(range(5, 0, -1), 1):
        row = [P(f"<b>{i} {risk.IMPACT[i][0]}</b>", small)]
        for ci, p in enumerate(range(1, 6), 1):
            n, cell_lv = mx.get((i, p), 0), risk.level(i * p)
            style.append(("BACKGROUND", (ci, ri), (ci, ri), colors.HexColor(COLOURS[cell_lv][1])))
            row.append(P(f"<b>{n}</b> {cell_lv}: {', '.join(ids[(i, p)][:6])}" + (" ..." if len(ids[(i, p)]) > 6 else "")
                         if n else f'<font color="#5d6675">{i * p}</font>', small))
        rows.append(row)
    story += [P("Risk matrix (impact × likelihood)", h2),
              KeepTogether(table(rows, [38 * mm] + [44.8 * mm] * 5, style))]

    # --- risk table
    rows = [["ID", "Risk", "Level", "Problem", "Rationale", "Remediation"]]
    for r in rated:
        est = " (estimate)" if r.get("estimated") else ""
        rows.append([P(f"<b>{r['id']}</b>", base), P(f"{r['risk']} ({r['impact']}×{r['probability']}){est}", base),
                     level_cell(r["level"]), P(t(r["title"], 400), base), P(t(r["probability_why"], 300), small),
                     P(t(r.get("fix") or "See the evidence.", 600), small)])
    story += [P("Risk table", h2),
              P("Sorted by risk. The evidence for each problem is in the appendix (every finding points to its R..).", muted),
              table(rows, [12 * mm, 24 * mm, 20 * mm, 78 * mm, 50 * mm, 78 * mm])]

    cve = next((sc for sc in rep["scans"] if sc["name"] == "cve" and sc["data"].get("now_detail")), None)
    if cve:
        from .cve import sources_text
        by = {}
        for v in cve["data"]["now_detail"]:
            by.setdefault(v["pkg"], []).append(v)
        sev = {x: i for i, x in enumerate(["critical", "high", "medium", "low"])}
        rows = [["Package", "CVEs", "Most severe", "KEV", "Installed -> available"]]
        for pkg, vs in sorted(by.items(), key=lambda kv: (min(sev.get(v["severity"], 3) for v in kv[1]), -len(kv[1])))[:30]:
            worst = min((v["severity"] for v in vs), key=lambda x: sev.get(x, 3))
            kev = ", ".join(v["cve"] for v in vs if v.get("kev")) or "—"
            rows.append([P(t(pkg), base), str(len(vs)), worst, P(t(kev), small),
                         P(t(f"{vs[0]['installed']} -> {vs[0]['available']}"), small)])
        story += [P("CVEs fixable now, by package", h2), P(t("Sources: " + sources_text(cve["data"])), muted),
                  table(rows, [60 * mm, 15 * mm, 25 * mm, 60 * mm, 102 * mm])]
        if len(by) > 30:
            story.append(P(f"... and {len(by) - 30} more packages (full list in report.json).", muted))

    story.append(P("Method", h2))
    story.append(P("<b>Risk = Impact × Likelihood</b>, each from 1 to 5. Levels: CRITICAL 15-25, HIGH 10-14, "
                   "MEDIUM 5-9, LOW 1-4. Likelihood is adjusted with what the tool measured (a network weakness on a "
                   "port nmap could not reach drops by 2; a CVE in the CISA KEV catalogue rises to 5). \"(estimate)\": "
                   "no specific rule, the values derive from the finding severity.", base))
    scale = [["Impact", "Meaning", "Likelihood", "Meaning"]]
    for k in range(5, 0, -1):
        scale.append([f"{k} {risk.IMPACT[k][0]}", P(risk.IMPACT[k][1], small),
                      f"{k} {risk.PROBABILITY[k][0]}", P(risk.PROBABILITY[k][1], small)])
    story.append(table(scale, [28 * mm, 103 * mm, 28 * mm, 103 * mm]))

    rows = [["Check", "Status", "Duration (s)", "Findings", "Notes"]]
    for sc in rep["scans"]:
        note = sc["findings"][0]["title"] if sc["status"] != "ok" and sc["findings"] else ""
        rows.append([t(sc["name"]), t(sc["status"]), str(int(sc.get("duration", 0))), str(len(sc["findings"])),
                     P(t(note, 200), small)])
    story += [P("Checks performed", h2),
              P("A <i>skipped</i> or <i>error</i> check verified NOTHING: the reason is in the Notes column.", muted),
              table(rows, [30 * mm, 22 * mm, 22 * mm, 18 * mm, 170 * mm])]
    if rep.get("tools"):
        story.append(P("Tools installed and removed on the target:", muted))
        for x in rep["tools"]:
            name = x["tool"] if x.get("package", "-") == "-" else x["package"]
            story.append(P(f"• <b>{t(name, 300)}</b>: {t(x['action'])}", small))

    story.append(P("Appendix: findings of each check", h2))
    order = {k: i for i, k in enumerate(SEVERITIES)}
    for sc in rep["scans"]:
        if not sc["findings"]:
            continue
        story.append(P(f"<b>{t(sc['name'])}</b>", base))
        for f in sorted(sc["findings"], key=lambda x: order[x["severity"]]):
            link = f" → <b>{t(f['issue'])}</b>" if f.get("issue") else ""
            det = f' — <font color="#5d6675">{t(f["detail"], 400)}</font>' if f.get("detail") else ""
            story.append(P(f"<b>{t(f['id'])}</b> [{t(f['severity'])}] {t(f['title'], 300)}{link}{det}", small))
        story.append(Spacer(1, 3))
    story += [Spacer(1, 6), P("The results are automatically collected indicators, not verdicts: every problem must "
                              "be verified before acting on it.", muted)]

    footer = f"ZeroStressRiskAssess — {clean_text(str(m.get('target', '')), 80)} — {m.get('timestamp', '')}"
    if not uni:
        footer = footer.encode("latin-1", "replace").decode("latin-1")

    def on_page(canvas, doc):
        canvas.saveState()
        canvas.setFont(regular, 7)
        canvas.setFillColor(colors.HexColor("#5d6675"))
        canvas.drawString(12 * mm, 7 * mm, footer)
        canvas.drawRightString(landscape(A4)[0] - 12 * mm, 7 * mm, f"page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(path if hasattr(path, "write") else str(path), pagesize=landscape(A4), leftMargin=12 * mm, rightMargin=12 * mm,
                            topMargin=12 * mm, bottomMargin=14 * mm, title=f"Risk assessment {m.get('target', '')}",
                            author="ZeroStressRiskAssess", subject="Risk assessment report")
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)


def pdf_bytes(rep: dict) -> bytes:
    import io
    buf = io.BytesIO()
    to_pdf(rep, buf)
    return buf.getvalue()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="zsra-pdf", description="Write report.pdf for an existing report")
    ap.add_argument("report", help="report folder (or its report.json)")
    args = ap.parse_args(argv)
    p = Path(args.report).expanduser()
    js = p if p.name.endswith(".json") else p / "report.json"
    if not available():
        print("ERROR: ReportLab is not installed: .venv/bin/pip install reportlab (or ./setup.sh)", file=sys.stderr)
        return 2
    try:
        rep = json.loads(js.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    out = js.with_suffix(".pdf")
    from .report import write_private_bytes
    write_private_bytes(out, pdf_bytes(rep))
    print(f"[+] {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
