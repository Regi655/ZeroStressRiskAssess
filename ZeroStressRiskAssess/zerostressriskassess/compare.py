"""Comparison of two runs on the same target: what was fixed, what is new, what is left, what changed level.

    zsra-compare BEFORE_DIR AFTER_DIR [-o comparison.md]

WHY: after a risk assessment the owner fixes things; at the next check the real question is not "what problems
does it have?" but "did the fixes work, and did new problems appear?".

The unit compared is the problem of the risk table (not the single finding): it is what the report rates and
what the owner acted on. How problems are paired (see fingerprint.py):
  1) same full key (checks that saw it + normalised title);
  2) for those left unpaired, same loose key (title without brackets), one to one, in order: the problem is the
     same but another check started seeing it, or a bracketed list changed.
A problem can also be REGROUPED rather than new or fixed: the correlation joins findings into one problem
("SSH login without password" joins the empty password of an account and PermitEmptyPasswords yes); if the empty password is fixed, the
other finding becomes a problem of its own. It was already there: the comparison says so ("regrouped"), comparing
the evidence findings of the two runs.
Pure functions (compare) + rendering: testable without a target.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .fingerprint import keys
from .report import LEVEL_ORDER, _md, write_private


def _problems(rep: dict) -> list:
    fx = {f["id"]: keys(sc["name"], f["title"])[0] for sc in rep.get("scans", []) for f in sc.get("findings", [])}
    out = []
    for r in rep.get("risks", []):
        full, loose = keys(r.get("scans", []), r["title"])
        out.append({"id": r["id"], "title": r["title"], "risk": r["risk"], "level": r["level"],
                    "full": full, "loose": loose,
                    "evidence": {fx[e] for e in r.get("evidence", []) if e in fx}})
    return out


def _regrouped(items, others) -> None:
    """Mark the problems whose evidence findings appear in a problem of the other run ("moved" = its ID there)."""
    for p in items:
        p["moved"] = next((o["id"] for o in others if p["evidence"] & o["evidence"]), None)


def compare(old: dict, new: dict) -> dict:
    """{"new": [...], "fixed": [...], "kept": [(before, after)], "worse": [...], "better": [...]}."""
    a, b = _problems(old), _problems(new)
    kept, used_a, used_b = [], set(), set()
    for key in ("full", "loose"):            # pass 1: full key; pass 2: loose key
        index = {}
        for i, p in enumerate(a):
            if i not in used_a:
                index.setdefault(p[key], []).append(i)
        for j, p in enumerate(b):
            if j in used_b or not index.get(p[key]):
                continue
            i = index[p[key]].pop(0)
            used_a.add(i)
            used_b.add(j)
            kept.append((a[i], p))
    _regrouped([p for j, p in enumerate(b) if j not in used_b], a)
    _regrouped([p for i, p in enumerate(a) if i not in used_a], b)
    by_risk = lambda p: (-p["risk"], p["title"])  # noqa: E731
    kept.sort(key=lambda pair: by_risk(pair[1]))
    return {
        "new": sorted((p for j, p in enumerate(b) if j not in used_b), key=by_risk),
        "fixed": sorted((p for i, p in enumerate(a) if i not in used_a), key=by_risk),
        "kept": kept,
        "worse": [pr for pr in kept if pr[1]["risk"] > pr[0]["risk"]],
        "better": [pr for pr in kept if pr[1]["risk"] < pr[0]["risk"]],
    }


def _line(p, other_run="") -> str:
    s = f"- **{p['level']} {p['risk']}** {_md(p['title'])} *({p['id']})*"
    if p.get("moved"):
        s += f" - regrouped: its evidence is also in {p['moved']} of the {other_run} run"
    return s


def to_markdown(old: dict, new: dict, c: dict) -> str:
    mo, mn, so, sn = old["meta"], new["meta"], old["summary"], new["summary"]
    counts = lambda s: ", ".join(f"{s['counts'].get(lv, 0)} {lv.lower()}" for lv in LEVEL_ORDER)  # noqa: E731
    L = [f"# Risk assessment comparison — {_md(mn.get('target', '?'))}", "",
         f"- Before: {mo.get('timestamp', '?')} (ZeroStressRiskAssess {_md(mo.get('version', '?'))}): "
         f"**{so['level']}** - {counts(so)}",
         f"- After:  {mn.get('timestamp', '?')} (ZeroStressRiskAssess {_md(mn.get('version', '?'))}): "
         f"**{sn['level']}** - {counts(sn)}", ""]
    if str(mo.get("timestamp", "")) > str(mn.get("timestamp", "")):   # "YYYY-MM-DD HH:MM": sorts as text
        # Seen on the Rocky lab (2026-10-22): the folders passed in reverse order turned the fixes into "new"
        # problems. Not swapped silently: the reader must know which order the table refers to.
        L += [f"> WARNING: 'before' ({mo.get('timestamp')}) is LATER than 'after' ({mn.get('timestamp')}): the two "
              "reports were probably given in reverse order, so 'fixed' and 'new' are swapped. Run again as "
              "zsra-compare EARLIER_REPORT LATER_REPORT.", ""]
    if mo.get("target") != mn.get("target"):
        L += [f"> WARNING: different targets ({_md(mo.get('target'))} / {_md(mn.get('target'))}): "
              "the comparison makes little sense.", ""]
    if mo.get("version") != mn.get("version"):
        L += ["> Different tool versions: a 'new' or 'fixed' problem may come from the tool (checks added or "
              "corrected) and not from the system. Verify by hand.", ""]
    if bool(mo.get("scope")) != bool(mn.get("scope")):
        L += ["> One of the two runs is an external reconnaissance only: the internal checks of the other one have "
              "no counterpart, so 'fixed' and 'new' are not meaningful for them.", ""]
    L += ["| | Problems |", "|---|---:|",
          f"| Fixed | {len(c['fixed'])} |", f"| New | {len(c['new'])} |", f"| Still present | {len(c['kept'])} |",
          f"| ...risk increased | {len(c['worse'])} |", f"| ...risk decreased | {len(c['better'])} |",
          f"| Regrouped (among new and fixed) | {sum(1 for p in c['new'] + c['fixed'] if p.get('moved'))} |", "",
          "A problem counts as fixed when the second run no longer reports it: verify that the check that found it "
          "ran in both (section *Checks performed* of each report).", ""]
    for title, items, other in (("New", c["new"], "earlier"), ("Fixed", c["fixed"], "later")):
        L += [f"## {title} ({len(items)})", ""] + ([_line(p, other) for p in items] or ["None."]) + [""]
    if any(p.get("moved") for p in c["new"] + c["fixed"]):
        L += ["*Regrouped*: the weakness was already there (or is still there) as evidence of another problem; "
              "what changed is how the findings are grouped, usually because a related finding was fixed.", ""]
    changed = [f"- {'INCREASED' if pr in c['worse'] else 'decreased'}: {_md(pr[1]['title'])} "
               f"({pr[0]['level']} {pr[0]['risk']} -> {pr[1]['level']} {pr[1]['risk']})"
               for pr in c["worse"] + c["better"]]
    L += [f"## Risk changed ({len(changed)})", ""] + (changed or ["None."]) + [""]
    L += [f"## Still present ({len(c['kept'])})", ""] + ([_line(pr[1]) for pr in c["kept"]] or ["None."])
    return "\n".join(L) + "\n"


def _load(path: str) -> dict:
    p = Path(path).expanduser()
    if p.is_dir():
        p = p / "report.json"
    rep = json.loads(p.read_text(encoding="utf-8"))
    if "risks" not in rep:
        raise ValueError(f"{p}: not a ZeroStressRiskAssess report (no risk table)")
    return rep


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="zsra-compare", description="Compare two reports of the same target")
    ap.add_argument("before", help="report folder (or report.json) of the earlier run")
    ap.add_argument("after", help="report folder (or report.json) of the later run")
    ap.add_argument("-o", "--output", help="save the comparison as Markdown (mode 600)")
    args = ap.parse_args(argv)
    try:
        old, new = _load(args.before), _load(args.after)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if str(old["meta"].get("timestamp", "")) > str(new["meta"].get("timestamp", "")):
        print("[!] The first report is LATER than the second: order probably reversed (see the warning in the "
              "comparison).", file=sys.stderr)
    md = to_markdown(old, new, compare(old, new))
    if args.output:
        write_private(Path(args.output).expanduser(), md)   # it describes the target's weaknesses, like the reports
        print(f"[+] Comparison saved to {args.output}")
    else:
        print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
