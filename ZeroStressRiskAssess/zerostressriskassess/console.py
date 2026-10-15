"""Interactive zsra console, opened by running `zsra` without arguments.

The direct command (`zsra HOST -u USER ...`) remains the primary interface because it runs everything in
one line and can be automated. The console targets interactive work: several assessments in a row, browsing
and opening reports, checking the external tools, with built-in help and TAB completion.

Console commands accept EXACTLY the same options and call the same code as the direct command (cli.main),
so there is a single assessment path.
"""
from __future__ import annotations

import cmd
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from . import __version__, banner

HISTORY = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "zsra" / "history"


class Console(cmd.Cmd):
    intro = ""
    doc_header = "Commands (help COMMAND for details):"
    undoc_header = ""
    ruler = ""

    def __init__(self, out_dir="./reports", stdin=None, stdout=None):
        super().__init__(stdin=stdin, stdout=stdout)
        self.out_dir = out_dir
        if stdin is not None:
            self.use_rawinput = False
        tty = getattr(self.stdout, "isatty", lambda: False)() and not os.environ.get("NO_COLOR")
        self.prompt = "\x1b[1;36mzsra\x1b[0m > " if tty else "zsra > "

    # ------------------------------------------------------------------ execution
    def _run(self, argv) -> int:
        """Run cli.main as the direct command would, without terminating the console."""
        from .cli import main
        try:
            return main(argv + ["--no-banner"])   # the console already showed the banner at startup
        except SystemExit as exc:      # argparse: --help or invalid options
            return exc.code if isinstance(exc.code, int) else 2
        except KeyboardInterrupt:
            self.stdout.write("\nInterrupted.\n")
            return 130

    def _split(self, line):
        try:
            return shlex.split(line)
        except ValueError as exc:
            self.stdout.write(f"Invalid line: {exc}\n")
            return None

    def _has_out_dir(self, argv):
        return any(a == "--out-dir" or a.startswith("--out-dir=") for a in argv)

    def emptyline(self):   # an empty line must not repeat the previous command (cmd.Cmd default)
        return False

    def default(self, line):
        self.stdout.write(f"Unknown command: {line.split()[0]}. Type 'help' for the list.\n")

    # ------------------------------------------------------------------ commands
    def do_scan(self, line):
        """scan HOST -u USER [options]
    Assess a machine over SSH: nmap and ssh-audit from here, then the internal checks.
    Same options as the direct command, e.g.:
      scan 192.168.1.50 -u admin -i ~/.ssh/id_ed25519
      scan server.lan -u admin --ask-sudo-pass --clamav-quick
    Full list of options: 'options'."""
        argv = self._split(line)
        if argv is None:
            return
        if not argv:
            self.stdout.write("Usage: scan HOST -u USER [options]   (help scan)\n")
            return
        self._run(argv + ([] if self._has_out_dir(argv) else ["--out-dir", self.out_dir]))

    def do_local(self, line):
        """local [options]
    Assess the machine zsra is running on (requires root: start zsra with sudo).
    Example: local --skip clamav"""
        argv = self._split(line)
        if argv is None:
            return
        self._run(["--local"] + argv + ([] if self._has_out_dir(argv) else ["--out-dir", self.out_dir]))

    def do_reports(self, line):
        """reports
    List the latest reports (newest first) with overall risk and number of problems."""
        rows = self._reports()
        if not rows:
            self.stdout.write(f"No reports in {self.out_dir}.\n")
            return
        self.stdout.write(f"{'N':>3}  {'Date':16}  {'Target':18}  {'Risk':9}  Problems\n")
        for n, (path, rep) in enumerate(rows[:15], 1):
            m, s = rep.get("meta", {}), rep.get("summary", {})
            self.stdout.write(f"{n:>3}  {m.get('timestamp', '?'):16}  {str(m.get('target', '?'))[:18]:18}  "
                              f"{s.get('level', '?'):9}  {len(rep.get('risks', []))}\n")
        self.stdout.write("To open one in the browser: open N\n")

    def do_open(self, line):
        """open [N]
    Open report N of the 'reports' list in the browser (without N: the most recent)."""
        rows = self._reports()
        if not rows:
            self.stdout.write(f"No reports in {self.out_dir}.\n")
            return
        try:
            n = int(line.strip() or "1")
            path = rows[n - 1][0].parent / "report.html"
        except (ValueError, IndexError):
            self.stdout.write("Invalid number: see 'reports'.\n")
            return
        if not path.exists():
            self.stdout.write(f"HTML report not found: {path}\n")
            return
        opener = shutil.which("xdg-open") or shutil.which("open")
        if not opener:
            self.stdout.write(f"Open it manually: {path}\n")
            return
        # Argument list, no shell: the path is never interpreted as a command.
        subprocess.Popen([opener, str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.stdout.write(f"Opened: {path}\n")

    def do_tools(self, line):
        """tools
    Check the external programs on the controller (nmap, ssh-audit, grype, trivy, Lynis)."""
        from .cli import DEFAULT_LYNIS
        for name, hint in (("nmap", "sudo apt install nmap"), ("ssh-audit", "sudo apt install ssh-audit"),
                           ("grype", "curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin"),
                           ("trivy", "see README, Requirements (Aqua's signed APT repository)")):
            where = shutil.which(name)
            self.stdout.write(f"  {'[ok]     ' if where else '[missing]'} {name:10} {where or hint}\n")
        ok = os.path.isfile(os.path.join(DEFAULT_LYNIS, "lynis"))
        self.stdout.write(f"  {'[ok]     ' if ok else '[missing]'} {'lynis':10} "
                          f"{DEFAULT_LYNIS if ok else './setup.sh (downloads it into vendor/lynis)'}\n")
        self.stdout.write("  Missing tools are skipped and reported as such.\n")

    def do_options(self, line):
        """options
    All options accepted by 'scan' and 'local' (the same as the direct command)."""
        from .cli import build_parser
        self.stdout.write(build_parser().format_help())

    def do_version(self, line):
        """version
    ZeroStressRiskAssess version."""
        self.stdout.write(f"ZeroStressRiskAssess {__version__}\n")

    def do_clear(self, line):
        """clear
    Clear the screen and show the banner again."""
        if getattr(self.stdout, "isatty", lambda: False)():
            self.stdout.write("\x1b[2J\x1b[H")
        banner.show(self.stdout)

    def do_exit(self, line):
        """exit
    Close the console (also Ctrl-D)."""
        return True

    do_quit = do_exit

    def do_EOF(self, line):   # Ctrl-D
        self.stdout.write("\n")
        return True

    def get_names(self):   # hide aliases and EOF from 'help'
        return [n for n in super().get_names() if n not in ("do_EOF", "do_quit")]

    # ------------------------------------------------------------------ helpers
    def _reports(self):
        rows = []
        for f in Path(self.out_dir).glob("**/report.json"):
            try:
                rows.append((f, json.loads(f.read_text(encoding="utf-8"))))
            except (OSError, ValueError):
                continue
        rows.sort(key=lambda r: r[0].stat().st_mtime, reverse=True)
        return rows


def _history(load: bool):
    try:
        import readline
    except ImportError:          # no readline (e.g. Windows): no history, the console still works
        return
    try:
        if load:
            if HISTORY.exists():
                readline.read_history_file(str(HISTORY))
        else:
            HISTORY.parent.mkdir(parents=True, exist_ok=True)
            readline.set_history_length(500)
            readline.write_history_file(str(HISTORY))
            os.chmod(HISTORY, 0o600)   # the history contains target IPs and user names: owner only
    except OSError:
        pass


def run(out_dir="./reports") -> int:
    banner.show()
    print("ZeroStressRiskAssess console. 'help' lists the commands, 'exit' or Ctrl-D quits.")
    print("Never type passwords into commands: use --ask-pass / --ask-sudo-pass.\n")
    _history(load=True)
    c = Console(out_dir=out_dir)
    try:
        while True:
            try:
                c.cmdloop()
                break
            except KeyboardInterrupt:   # Ctrl-C at the prompt cancels the line instead of exiting
                print("^C")
    finally:
        _history(load=False)
    return 0


if __name__ == "__main__":
    sys.exit(run())
