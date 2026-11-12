"""The look of ZeroStressRiskAssessWeb, the portal of the suite, for the zsra web interface.

The colours are those of the portal's src/main/resources/static/css/app.css: white and orange, orange only for
identity and action, the risk levels in the colours of the zsra HTML report; the dark theme is the portal's
"negative" of the light one. Two places use them:
  - streamlit_flags(): Streamlit's own theme (widgets, tables, links, badges), light and dark, passed by zsra-web
    on the command line; the viewer's system preference picks one, Streamlit's settings menu can switch;
  - css(): what Streamlit has no setting for (the orange bar on top, the brand, cards, the summary boxes).
"""
from __future__ import annotations

LIGHT = dict(bg="#ffffff", fg="#1c1917", muted="#57534e", line="#e7e5e4", line_strong="#d6d3d1",
             brand="#ea580c", accent="#c2410c", accent_hover="#9a3412", accent_fg="#ffffff", accent_tint="#fff4ec",
             accent_line="#fdba8c", input_bg="#fff1e5", surface="#fffaf5", surface_line="#f1e2d6",
             surface_top="#fdba8c", code="#f5f5f4",
             crit="#b42318", crit_bg="#fde4e1", high="#c4520c", high_bg="#feead9",
             med="#8a6a00", med_bg="#fdf3c7", low="#2e7d32", low_bg="#e3f2e4")
DARK = dict(bg="#000000", fg="#e8e5e3", muted="#b1ada8", line="#1b1918", line_strong="#2e2b29",
            brand="#f36115", accent="#f3723d", accent_hover="#ed8765", accent_fg="#000000", accent_tint="#130800",
            accent_line="#733002", input_bg="#1a0c00", surface="#0a0500", surface_line="#291a0e",
            surface_top="#733002", code="#0b0b0a",
            crit="#e7564b", crit_bg="#1e0502", high="#f3813b", high_bg="#261201",
            med="#ffdf75", med_bg="#382e02", low="#82d186", low_bg="#0d1c0e")

LEVEL_KEYS = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low"}


def palette(kind: str | None) -> dict:
    return DARK if kind == "dark" else LIGHT


def streamlit_flags() -> list:
    """--theme.light.* and --theme.dark.* options for `streamlit run`."""
    # font: the portal's system-ui stack is what "sans-serif" resolves to on Linux, Windows and macOS
    flags = ["--theme.baseRadius=8px", "--theme.buttonRadius=8px", "--theme.showWidgetBorder=true",
             "--theme.font=sans-serif"]
    for name, c in (("light", LIGHT), ("dark", DARK)):
        t = {"primaryColor": c["accent"], "backgroundColor": c["bg"], "secondaryBackgroundColor": c["input_bg"],
             "textColor": c["fg"], "linkColor": c["accent"], "borderColor": c["surface_line"],
             "codeBackgroundColor": c["code"], "codeTextColor": c["fg"], "dataframeHeaderBackgroundColor": c["surface"],
             "redColor": c["crit"], "redBackgroundColor": c["crit_bg"], "redTextColor": c["crit"],
             "orangeColor": c["high"], "orangeBackgroundColor": c["high_bg"], "orangeTextColor": c["high"],
             "yellowColor": c["med"], "yellowBackgroundColor": c["med_bg"], "yellowTextColor": c["med"],
             "greenColor": c["low"], "greenBackgroundColor": c["low_bg"], "greenTextColor": c["low"]}
        flags += [f"--theme.{name}.{k}={v}" for k, v in t.items()]
    return flags


def css(kind: str | None) -> str:
    c = palette(kind)
    return f"""<style>
/* the bar of the brand, as in the portal: one strip of orange on top */
[data-testid="stAppViewContainer"] {{ border-top: 4px solid {c['brand']}; }}
[data-testid="stHeader"] {{ background: transparent; }}
.block-container {{ max-width: 1180px; padding-top: 1.2rem; }}
.zsra-brand {{ font-weight: 800; font-size: 1.15rem; color: {c['fg']}; letter-spacing: .01em; white-space: nowrap;
  margin: 6px 0 0; }}
.zsra-brand::before {{ content: ""; display: inline-block; width: 14px; height: 14px; border-radius: 3px;
  background: {c['brand']}; margin-right: 8px; vertical-align: -2px; }}
.zsra-brand span {{ color: {c['accent']}; }}
.zsra-brand small {{ color: {c['muted']}; font-weight: 400; font-size: .8rem; margin-left: 8px; }}
hr.zsra-line {{ border: 0; border-top: 1px solid {c['line']}; margin: 4px 0 12px; }}
/* boxes of content: the portal's peach surface with a light orange strip on top */
[data-testid="stVerticalBlockBorderWrapper"]:has(> div > [data-testid="stVerticalBlock"]) ,
[data-testid="stForm"] {{ background: {c['surface']}; border: 1px solid {c['surface_line']} !important;
  border-top: 3px solid {c['surface_top']} !important; border-radius: 10px; }}
/* where you type: peach field with an orange border */
[data-baseweb="input"], [data-baseweb="select"] > div, [data-baseweb="textarea"] {{ border-color: {c['accent_line']} !important; }}
/* buttons: solid orange (primary), white with grey border (secondary) */
button[kind="primary"], button[kind="primaryFormSubmit"] {{ font-weight: 600; }}
button[kind="secondary"], button[kind="secondaryFormSubmit"] {{ background: {c['bg']}; border-color: {c['line_strong']}; }}
button[kind="secondary"]:hover, button[kind="secondaryFormSubmit"]:hover {{ background: {c['accent_tint']};
  color: {c['accent']}; border-color: {c['accent_line']}; }}
h1, h2, h3 {{ font-weight: 700; }}
.zsra-summary {{ display: flex; flex-wrap: wrap; gap: 12px; margin: 8px 0 14px; }}
.zsra-overall {{ flex: 1 1 220px; border-radius: 10px; padding: 14px 16px; font-weight: 600; }}
.zsra-overall b {{ font-size: 2rem; display: block; line-height: 1.2; }}
.zsra-count {{ flex: 0 1 120px; border-radius: 10px; padding: 10px; text-align: center; font-size: .85rem; }}
.zsra-count b {{ display: block; font-size: 1.7rem; line-height: 1.2; }}
""" + "".join(f".lv-{k} {{ background: {c[k + '_bg']}; color: {c[k]}; }}\n" for k in LEVEL_KEYS.values()) + f"""
.zsra-matrix {{ border-collapse: separate; border-spacing: 3px; }}
.zsra-matrix td, .zsra-matrix th {{ width: 3.4em; height: 2.7em; text-align: center; border-radius: 6px;
  font-size: .9rem; color: {c['muted']}; }}
.zsra-matrix td {{ color: {c['accent_fg']}; font-weight: 700; font-size: 1.1rem; }}
.zsra-matrix td.empty {{ opacity: .35; }}
.zsra-foot {{ color: {c['muted']}; font-size: .8rem; border-top: 1px solid {c['line']}; margin-top: 32px;
  padding-top: 10px; }}
</style>"""


def level_colour(kind: str | None, level: str) -> str:
    return palette(kind)[LEVEL_KEYS.get(level, "low")]
