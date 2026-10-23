"""Assessment of several machines from an inventory file, with a summary table.

    zsra-inventory hosts.txt [--yes] [--out-dir DIR] [-- OPTIONS FOR EVERY MACHINE]

The inventory is a text file with ONE zsra command line per machine, the same arguments as the direct command
(without "zsra"). Empty lines and lines starting with # are ignored; "# ..." at the end of a line is a comment.

    # web servers
    192.168.1.50 -u admin -i ~/.ssh/id_ed25519
    192.168.1.51 -u admin --ask-pass --skip clamav
    # a machine that must not be touched: from outside only
    192.168.1.60 --recon-only

WHY the same syntax as the direct command: nothing new to learn, every option and every validation of zsra
applies unchanged, and a line can be tried on its own by putting "zsra" in front of it.

How it runs:
  1. every line is parsed BEFORE anything starts: a mistake on line 7 stops the run before machine 1 is touched;
  2. ONE authorisation question for the whole list (it shows every target);
  3. the machines are assessed one after the other (in parallel the passwords asked with --ask-pass would mix
     on the terminal, and the controller's nmap/Grype would compete for the CPU); a machine that fails does not
     stop the others;
  4. reports and summary go into one directory: inventory_<date>/ (summary.md, summary.html, summary.json and
     one report directory per machine). Ctrl-C stops the run and still writes the summary of what was done.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import shlex
import sys
from datetime import datetime
from html import escape
from pathlib import Path

from . import __version__
from .htmlreport import CSS, LV_CLASS
from .models import clean_text
from .report import LEVEL_ORDER, write_private

FORBIDDEN = {"--out-dir": "the inventory decides where the reports go",
             "--recover": "a cleanup is run on one machine at a time with zsra",
             "--yes": "the authorisation is asked once for the whole inventory"}
RANK = {lv: i for i, lv in enumerate(LEVEL_ORDER)}


class InventoryError(ValueError):
    pass


def parse_inventory(text: str, common=()) -> list:
    """Inventory text -> [{"line": n, "argv": [...], "target": str}]. Each line is checked with zsra's own parser.
    Pure function except for argparse's error message (captured)."""
    from .cli import build_parser
    out = []
    for n, raw in enumerate(text.splitlines(), 1):
        try:
            argv = shlex.split(raw, comments=True)
        except ValueError as exc:
            raise InventoryError(f"line {n}: {exc}") from None
        if not argv:
            continue
        argv += list(common)
        bad = [o for o in argv if o.split("=")[0] in FORBIDDEN]
        if bad:
            raise InventoryError(f"line {n}: {bad[0]} is not allowed in an inventory ({FORBIDDEN[bad[0].split('=')[0]]})")
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                args = build_parser().parse_args(argv)
        except SystemExit:   # argparse reports the error on stderr and exits: turned into the line's error
            msg = (err.getvalue().strip().splitlines() or ["invalid options"])[-1]
            raise InventoryError(f"line {n}: {msg}") from None
        if args.local == bool(args.host):
            raise InventoryError(f"line {n}: a host, OR --local")
        if args.host and not args.user and not args.recon_only:
            raise InventoryError(f"line {n}: {args.host} requires -u USER (or --recon-only)")
        # Files named in the line are checked now, before the authorisation question and before any machine is
        # touched (first real inventory, 2026-10-23: a wrong -i path failed four times, one machine after another).
        if args.key and not os.path.isfile(os.path.expanduser(args.key)):
            raise InventoryError(f"line {n}: -i/--key: file not found: {os.path.expanduser(args.key)}")
        # Also checked BEFORE starting: otherwise a missing variable is discovered only after the machines
        # before it have been assessed (minutes each).
        if getattr(args, "sudo_pass_env", None) and not os.environ.get(args.sudo_pass_env):
            raise InventoryError(f"line {n}: --sudo-pass-env: variable {args.sudo_pass_env} is empty or undefined "
                                 f"(set it with: read -rsp 'password: ' {args.sudo_pass_env}; "
                                 f"export {args.sudo_pass_env})")
        target = "this machine (--local)" if args.local else args.host
        out.append({"line": n, "argv": argv, "target": target + (" (recon only)" if args.recon_only else "")})
    if not out:
        raise InventoryError("the inventory contains no machine")
    locals_ = [m for m in out if "--local" in m["argv"]]
    if len(locals_) > 1:
        raise InventoryError(f"line {locals_[1]['line']}: --local appears more than once")
    return out


def run_inventory(machines: list, out_dir: str, log=print, run_one=None) -> dict:
    """Assess each machine with zsra (cli.main); returns the summary. run_one(argv, result) -> rc, for the tests."""
    if run_one is None:
        from .cli import main as run_one
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    d = Path(out_dir).expanduser() / f"inventory_{ts}"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)   # reports of several machines: their weaknesses, readable by the author only
    rows, interrupted = [], False
    for i, m in enumerate(machines, 1):
        log(f"\n==> [{i}/{len(machines)}] {m['target']}  (inventory line {m['line']})")
        result, err = {}, _Tee(sys.stderr)
        try:
            with contextlib.redirect_stderr(err):
                rc = run_one(m["argv"] + ["--yes", "--no-banner", "--out-dir", str(d)], result)
        except SystemExit as exc:     # an option error found by zsra at run time (e.g. key file missing)
            rc = exc.code if isinstance(exc.code, int) else 2
        except KeyboardInterrupt:
            rows.append(_row(m, 130, {}, d))
            interrupted = True
            log("\nInventory interrupted by the user: the summary covers the machines done so far.")
            break
        rows.append(_row(m, rc, result.get("report") or {}, d, err.reason()))
    for m in machines[len(rows):]:
        rows.append({"line": m["line"], "target": m["target"], "status": "not run", "level": "", "counts": {},
                     "problems": 0, "report": ""})
    summary = {"created": datetime.now().isoformat(timespec="seconds"), "version": __version__,
               "interrupted": interrupted, "machines": rows}
    write_private(d / "summary.json", json.dumps(summary, indent=2, ensure_ascii=False))
    write_private(d / "summary.md", to_markdown(summary))
    write_private(d / "summary.html", to_html(summary))
    summary["dir"] = str(d)
    return summary


class _Tee(io.TextIOBase):
    """stderr that still reaches the terminal and is also kept, so the summary can say WHY a machine failed (first
    real inventory, 2026-10-22: four machines "error (exit code 2)" and the reasons only on the scrolled terminal)."""

    def __init__(self, real):
        self.real, self.buf = real, []

    def write(self, s):
        self.buf.append(s)
        return self.real.write(s)

    def flush(self):
        self.real.flush()

    def reason(self) -> str:
        lines = [x.strip() for x in "".join(self.buf).splitlines() if x.strip()]
        err = [x for x in lines if x.startswith("ERROR") or ": error:" in x]
        return clean_text((err or lines or [""])[-1], 300)


def _row(m, rc, rep, d: Path, reason: str = "") -> dict:
    s = rep.get("summary") or {}
    path = (rep.get("paths") or {}).get("html", "")
    status = {0: "ok", 1: "aborted", 130: "interrupted"}.get(rc, f"error (exit code {rc})") if not s else "ok"
    if status != "ok" and reason:
        status += f": {reason}"
    return {"line": m["line"], "target": m["target"], "status": status, "level": s.get("level", ""),
            "counts": s.get("counts", {}), "problems": len(rep.get("risks") or []),
            "report": os.path.relpath(path, d) if path else ""}


def _order(rows):
    """Worst machine first: overall level, then number of critical and high problems."""
    return sorted(rows, key=lambda r: (RANK.get(r["level"], 9), -r["counts"].get("CRITICAL", 0),
                                       -r["counts"].get("HIGH", 0), r["line"]))


def to_markdown(summary: dict) -> str:
    rows = summary["machines"]
    done = [r for r in rows if r["level"]]
    L = ["# Risk assessment — inventory summary", "",
         f"{len(rows)} machines, {len(done)} assessed ({summary['created'][:16].replace('T', ' ')}, "
         f"ZeroStressRiskAssess {summary['version']}).", ""]
    if summary.get("interrupted"):
        L += ["> **Interrupted**: the machines marked *not run* were not assessed.", ""]
    L += ["Sorted from the worst machine. Each report is in its own directory next to this file.", "",
          "| Target | Overall | Critical | High | Medium | Low | Status | Report |", "|---|---|---:|---:|---:|---:|---|---|"]
    for r in _order(rows):
        c = r["counts"]
        L.append(f"| {r['target']} | {('**' + r['level'] + '**') if r['level'] else '-'} | "
                 + " | ".join(str(c.get(lv, 0)) if r["level"] else "-" for lv in LEVEL_ORDER)
                 + f" | {r['status']} | {r['report'] or '-'} |")
    L += ["", "A machine with an error or not run was NOT assessed: its absence of problems means nothing."]
    return "\n".join(L) + "\n"


def to_html(summary: dict) -> str:
    rows = []
    for r in _order(summary["machines"]):
        c, lv = r["counts"], r["level"]
        badge = f'<span class="badge {LV_CLASS[lv]}">{lv}</span>' if lv in LV_CLASS else "-"
        link = f'<a href="{escape(r["report"])}">report</a>' if r["report"] else "-"
        rows.append(f"<tr><td>{escape(r['target'])}</td><td>{badge}</td>"
                    + "".join(f"<td>{c.get(x, 0) if lv else '-'}</td>" for x in LEVEL_ORDER)
                    + f"<td>{escape(r['status'])}</td><td>{link}</td></tr>")
    note = "<p><b>Interrupted</b>: the machines marked <i>not run</i> were not assessed.</p>" if summary.get(
        "interrupted") else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Risk — inventory</title><style>{CSS}</style></head><body><main>
<h1>Risk assessment — inventory summary</h1>
<div class="card">{note}<p>{len(summary['machines'])} machines, ZeroStressRiskAssess {escape(summary['version'])},
{escape(summary['created'][:16].replace('T', ' '))}. Sorted from the worst machine.</p>
<div class="scroll"><table><tr><th>Target</th><th>Overall</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th>
<th>Status</th><th>Report</th></tr>{''.join(rows)}</table></div>
<p class="muted">A machine with an error or not run was NOT assessed: its absence of problems means nothing.</p></div>
</main></body></html>
"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="zsra-inventory", description="Assess several machines from an inventory file")
    ap.add_argument("inventory", help="text file: one zsra command line per machine (see zsra-inventory --help)")
    ap.add_argument("--out-dir", default="./reports", help="where inventory_<date>/ is created (default ./reports)")
    ap.add_argument("--yes", action="store_true", help="do not ask for the authorisation confirmation")
    ap.epilog = ("Any other option, after the file name, is added to EVERY line: zsra-inventory hosts.txt --skip clamav "
                 "(also accepted after --: zsra-inventory hosts.txt -- --skip clamav)")
    argv = list(sys.argv[1:] if argv is None else argv)
    common = argv[argv.index("--") + 1:] if "--" in argv else []
    # Unknown options are zsra options for every machine (the user's first try was "hosts.txt --skip clamav" and
    # argparse refused it). They are validated anyway, line by line, by zsra's own parser in parse_inventory().
    args, extra = ap.parse_known_args(argv[:argv.index("--")] if "--" in argv else argv)
    common = extra + common
    try:
        machines = parse_inventory(Path(args.inventory).expanduser().read_text(encoding="utf-8"), common)
    except (OSError, InventoryError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"Inventory: {len(machines)} machines")
    for m in machines:
        print(f"  line {m['line']:>3}: {m['target']}")
    if not (args.yes or input("Do you have the authorisation of the owners of ALL these systems? [yes/no] ")
            .strip().lower() in ("yes", "y")):
        print("Aborted.")
        return 1
    s = run_inventory(machines, args.out_dir)
    print("\n" + to_markdown(s))
    print(f"Summary: {s['dir']}/summary.html")
    return 0 if all(r["status"] == "ok" for r in s["machines"]) else 2


if __name__ == "__main__":
    sys.exit(main())
