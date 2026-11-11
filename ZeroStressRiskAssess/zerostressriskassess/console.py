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
        # \x01 ... \x02 tell readline that the colour codes take no space on screen: without them readline
        # miscounts the prompt width, and history (arrow up) and backspace redraw only part of the line.
        self.prompt = "\x01\x1b[1;36m\x02zsra\x01\x1b[0m\x02 > " if tty else "zsra > "

    # ------------------------------------------------------------------ execution
    def _run(self, argv, main=None) -> int:
        """Run cli.main (or another command's main) as the direct command would, without terminating the console."""
        if main is None:
            from .cli import main as cli_main
            main, argv = cli_main, argv + ["--no-banner"]   # the console already showed the banner at startup
        try:
            return main(argv)
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

    def precmd(self, line):
        # "zsra scan ..." typed out of habit inside the console: drop the redundant program name.
        parts = line.split(None, 1)
        if parts and parts[0] == "zsra":
            line = parts[1] if len(parts) > 1 else ""
        return line

    def postcmd(self, stop, line):
        _restore_tty()   # ssh, getpass or an interrupted command may leave the terminal without echo/line editing
        return stop

    def _fix_host_flag(self, argv):
        """'-h HOST' (habit from other tools) would show the help: here -h is help, the host is positional."""
        if len(argv) >= 2 and argv[0] == "-h" and not argv[1].startswith("-"):
            self.stdout.write(f"Note: -h is help; the host is written without options (scan {argv[1]} ...).\n")
            return argv[1:]
        return argv

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
        argv = self._fix_host_flag(argv)
        self._run(argv + ([] if self._has_out_dir(argv) else ["--out-dir", self.out_dir]))

    def do_recon(self, line):
        """recon HOST [options]
    External reconnaissance only: nmap, ssh-audit, DNS and MySQL probes from here.
    No login: nothing is installed, run or written on the target (e.g. a machine that may be compromised
    and must not be contaminated). Examples:
      recon 192.168.1.50
      recon ns1.lab --dns-zone example.lab --nmap-ports -"""
        argv = self._split(line)
        if argv is None:
            return
        if not argv:
            self.stdout.write("Usage: recon HOST [options]   (help recon)\n")
            return
        argv = self._fix_host_flag(argv)
        self._run(argv + ["--recon-only"] + ([] if self._has_out_dir(argv) else ["--out-dir", self.out_dir]))

    def do_finalize(self, line):
        """finalize REPORT_DIR --recipient KEY [--sign-key KEY] [--omit ID --reason TEXT] [--upload ...]
    Report phase 2: omit the details too sensitive to circulate, encrypt with age for the recipient,
    sign with your SSH key and, with --upload, copy ONLY the encrypted file to the target. Example:
      finalize reports/192.168.1.50_20261020-1600 --recipient age1... --sign-key ~/.ssh/id_ed25519
    All options: finalize --help. Same as the zsra-finalize command."""
        from .finalize import main as finalize_main
        argv = self._split(line)
        if argv is None:
            return
        if not argv:
            self.stdout.write("Usage: finalize REPORT_DIR --recipient KEY [options]   (help finalize)\n")
            return
        self._run(argv, finalize_main)

    def do_compare(self, line):
        """compare BEFORE_DIR AFTER_DIR [-o FILE.md]
    Compare two reports of the same target: problems fixed, new, still present, risk changed.
    Example: compare reports/192.168.1.50_20261001-1000 reports/192.168.1.50_20261020-1600
    Same as the zsra-compare command."""
        from .compare import main as compare_main
        argv = self._split(line)
        if argv is None:
            return
        if len(argv) < 2:
            self.stdout.write("Usage: compare BEFORE_DIR AFTER_DIR [-o FILE.md]   (help compare)\n")
            return
        self._run(argv, compare_main)

    def do_inventory(self, line):
        """inventory FILE [--yes] [-- OPTIONS FOR EVERY MACHINE]
    Assess several machines: FILE has one zsra command line per machine (# for comments). One authorisation
    for all, one machine after the other, summary table sorted from the worst. Example:
      inventory hosts.txt -- --skip clamav
    Same as the zsra-inventory command."""
        from .inventory import main as inventory_main
        argv = self._split(line)
        if argv is None:
            return
        if not argv:
            self.stdout.write("Usage: inventory FILE [-- OPTIONS]   (help inventory)\n")
            return
        head = argv[:argv.index("--")] if "--" in argv else argv   # after "--" the options go to every machine
        if not self._has_out_dir(head):
            argv = [argv[0], "--out-dir", self.out_dir] + argv[1:]
        self._run(argv, inventory_main)

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
        self.stdout.write("To open one in the browser: open N   ·   to send one to the portal: upload N\n")

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

    def do_portal(self, line):
        """portal login URL [--auto] [--ca-file CA] | check | status | upload DIR... | logout
    The ZeroStressRiskAssessWeb portal of the suite: save the address and the API token (asked without echo),
    check it, upload reports. Example:
      portal login https://zsra.example.org --auto
    Same as the zsra-portal command."""
        from .portal import main as portal_main
        argv = self._split(line)
        if argv is None:
            return
        if not argv:
            self.stdout.write("Usage: portal login URL | check | status | upload DIR | logout   (help portal)\n")
            return
        self._run(argv, portal_main)

    def do_upload(self, line):
        """upload [N]
    Upload report N of the 'reports' list to the portal (without N: the most recent). Configure it first with
    'portal login URL'."""
        from .portal import upload_report
        rows = self._reports()
        if not rows:
            self.stdout.write(f"No reports in {self.out_dir}.\n")
            return
        try:
            n = int(line.strip() or "1")
            path = rows[n - 1][0].parent
        except (ValueError, IndexError):
            self.stdout.write("Invalid number: see 'reports'.\n")
            return
        upload_report(path, log=lambda m: self.stdout.write(m + "\n"))

    def do_tools(self, line):
        """tools
    Check the external programs on the controller (nmap, ssh-audit, grype, trivy, Lynis)."""
        for name, ok, where in tools_status():
            self.stdout.write(f"  {'[ok]     ' if ok else '[missing]'} {name:10} {where}\n")
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
        return list_reports(self.out_dir)


def list_reports(out_dir):
    """[(path of report.json, parsed report)], newest first. Unreadable files are skipped."""
    rows = []
    for f in Path(out_dir).glob("**/report.json"):
        try:
            rows.append((f, json.loads(f.read_text(encoding="utf-8"))))
        except (OSError, ValueError):
            continue
    rows.sort(key=lambda r: r[0].stat().st_mtime, reverse=True)
    return rows


def tools_status():
    """[(name, present, path or how to install it)] for the external programs used on the controller."""
    from .cli import DEFAULT_LYNIS
    rows = []
    for name, hint in (("nmap", "sudo apt install nmap"), ("ssh-audit", "sudo apt install ssh-audit"),
                       ("grype", "curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin"),
                       ("trivy", "see README, Requirements (Aqua's signed APT repository)")):
        where = shutil.which(name)
        rows.append((name, bool(where), where or hint))
    ok = os.path.isfile(os.path.join(DEFAULT_LYNIS, "lynis"))
    rows.append(("lynis", ok, DEFAULT_LYNIS if ok else "./setup.sh (downloads it into vendor/lynis)"))
    return rows


_TTY_STATE = None


def _save_tty():
    global _TTY_STATE
    try:
        import termios
        _TTY_STATE = termios.tcgetattr(sys.stdin.fileno())
    except (ImportError, OSError, ValueError, AttributeError):   # not a terminal, or no termios (Windows)
        _TTY_STATE = None


def _restore_tty():
    if _TTY_STATE is None:
        return
    try:
        import termios
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, _TTY_STATE)
    except (ImportError, OSError, ValueError):
        pass


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
    _save_tty()
    c = Console(out_dir=out_dir)
    try:
        while True:
            try:
                c.cmdloop()
                break
            except KeyboardInterrupt:   # Ctrl-C at the prompt cancels the line instead of exiting
                print("^C")
                _restore_tty()
    finally:
        _restore_tty()
        _history(load=False)
    return 0


if __name__ == "__main__":
    sys.exit(run())
