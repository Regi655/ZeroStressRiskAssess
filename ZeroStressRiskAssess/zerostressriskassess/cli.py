"""`zsra` command line: a single command runs the checks and produces the risk table.

zsra 192.168.1.50 -u admin -i ~/.ssh/id_ed25519      # from another machine, over SSH
sudo .venv/bin/zsra --local                          # on the machine itself
zsra                                                 # interactive console (console.py)
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from . import __version__, banner
from .models import Options
from .orchestrator import assess, recon, recover
from .scanners import ALL_NAMES
from .ssh_client import Local, NoLogin, Remote
from .validate import valid_host, valid_ports

DEFAULT_LYNIS = str(Path(__file__).resolve().parent.parent / "vendor" / "lynis")


def build_parser():
    ap = argparse.ArgumentParser(prog="zsra",
                                 epilog="Without arguments, zsra opens its interactive console.",
                                 description="Risk assessment of a Linux machine (Ubuntu/Debian, RHEL family): "
                                             "risk = impact × likelihood")
    ap.add_argument("host", nargs="?", help="target IP or hostname (omitted with --local)")
    ap.add_argument("--local", action="store_true", help="assess the machine running the command (no SSH)")
    ap.add_argument("--recon-only", action="store_true",
                    help="external reconnaissance only: no login, nothing run or written on the target")
    ap.add_argument("--dns-zone", nargs="+", default=[], metavar="ZONE",
                    help="DNS zones to test for zone transfer (AXFR) from this machine")
    ap.add_argument("-u", "--user", help="SSH user (root, or a sudo user)")
    ap.add_argument("-p", "--port", type=int, default=22, help="SSH port (default 22)")
    ap.add_argument("-i", "--key", help="SSH private key")
    ap.add_argument("--ask-pass", action="store_true", help="prompt for the SSH user's password")
    ap.add_argument("--ask-key-pass", action="store_true", help="prompt for the passphrase of the -i key")
    sp = ap.add_mutually_exclusive_group()
    sp.add_argument("--ask-sudo-pass", action="store_true", help="prompt for the sudo password")
    sp.add_argument("--sudo-pass-env", metavar="VARIABLE",
                    help="read the sudo password from the given environment variable (automation, lab)")
    ap.add_argument("--accept-new-hostkey", action="store_true",
                    help="accept the host key if the target is not in known_hosts (first contact only!)")
    ap.add_argument("--lynis-dir", default=DEFAULT_LYNIS, metavar="DIR",
                    help=f"Lynis copy to bring to the target (default {DEFAULT_LYNIS})")
    ap.add_argument("--nmap-ports", default="", help="nmap ports: '1-1024,8080'; '-' = all; empty = top 1000")
    ap.add_argument("--no-nse", action="store_true", help="nmap without NSE scripts (ports and versions only)")
    ap.add_argument("--nse-tls", action="store_true", help="also run ssl-enum-ciphers (TLS protocols and ciphers)")
    cl = ap.add_mutually_exclusive_group()
    cl.add_argument("--clamav-quick", action="store_true", help="ClamAV on typical malware locations only (fast)")
    cl.add_argument("--clamav-full", action="store_true", help="ClamAV on the whole disk (slow)")
    ap.add_argument("--skip", nargs="*", default=[], choices=ALL_NAMES, metavar="CHECK",
                    help="checks to skip: " + ", ".join(ALL_NAMES))
    ap.add_argument("--scan-timeout", type=int, default=60, metavar="MINUTES", help="maximum time per check")
    ap.add_argument("--out-dir", default="./reports", help="report directory (default ./reports)")
    ap.add_argument("--keep-tools", action="store_true", help="do NOT remove ClamAV and chkrootkit at the end (debugging)")
    ap.add_argument("--no-install", action="store_true",
                    help="install NOTHING on the target: ClamAV, chkrootkit and smartmontools only if already present")
    ap.add_argument("--recover", action="store_true", help="clean up the target after an interrupted run")
    ap.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    ap.add_argument("--no-banner", action="store_true", help="do not show the startup banner (also: ZSRA_NO_BANNER=1)")
    ap.add_argument("--version", action="version", version=f"ZeroStressRiskAssess {__version__}")
    return ap


def main(argv=None, result=None) -> int:
    """result: optional dict, filled with {"report": ...} when an assessment completes (used by inventory.py)."""
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        # `zsra` alone opens the interactive console (console.py); with arguments everything runs in one command.
        from .console import run
        return run()
    ap = build_parser()
    args = ap.parse_args(argv)
    if not args.no_banner:
        banner.show()
    if args.local == bool(args.host):
        ap.error("specify a host to assess over SSH, OR --local for this machine")
    if args.host and not valid_host(args.host):
        ap.error("invalid host: IP address or name (letters, digits, dots, hyphens)")
    if args.recon_only and (args.local or args.recover):
        ap.error("--recon-only works from outside: it cannot be combined with --local or --recover")
    if args.no_nse and args.nse_tls:
        ap.error("--no-nse and --nse-tls exclude each other")
    for z in args.dns_zone:
        if not valid_host(z.rstrip(".")):
            ap.error(f"--dns-zone: invalid zone name: {z}")
    if args.host and not args.user and not args.recon_only:
        ap.error("a host requires -u USER (or --recon-only for an external assessment without login)")
    if not valid_ports(args.nmap_ports):
        ap.error("invalid --nmap-ports: only digits, commas, hyphens, T: and U: are allowed")
    if args.no_install and args.keep_tools:
        ap.error("--no-install and --keep-tools exclude each other (with --no-install nothing is installed)")
    if args.ask_key_pass and not args.key:
        ap.error("--ask-key-pass requires -i/--key")
    # "~" is expanded by the shell, but not inside the zsra console (it splits the line itself, with no shell
    # in between): expanding here makes both work the same way.
    for name in ("key", "lynis_dir", "out_dir"):
        if getattr(args, name):
            setattr(args, name, os.path.expanduser(getattr(args, name)))
    # Checked BEFORE any work: otherwise a wrong path is discovered only after nmap and ssh-audit have run.
    if args.key and not os.path.isfile(args.key):
        ap.error(f"-i/--key: file not found: {args.key}")
    if args.key and not os.access(args.key, os.R_OK):
        ap.error(f"-i/--key: file not readable by the current user: {args.key}")
    if not 5 <= args.scan_timeout <= 600:
        ap.error("--scan-timeout: between 5 and 600 minutes")

    if args.recon_only:
        return _recon(args, result)

    spwd = getpass.getpass("sudo password: ") if args.ask_sudo_pass else None
    if args.sudo_pass_env:
        # Environment variable rather than argument: arguments are visible to every user through `ps`, a
        # process environment only to its owner and root. It should still be set for the single command only.
        spwd = os.environ.get(args.sudo_pass_env)
        if not spwd:
            ap.error(f"--sudo-pass-env: variable {args.sudo_pass_env} is empty or undefined")
    if args.local:
        rem = Local(sudo_password=spwd)
    else:
        kpwd = getpass.getpass("Key passphrase: ") if args.ask_key_pass else None
        pwd = getpass.getpass("SSH user password: ") if args.ask_pass else None
        rem = Remote(args.host, args.user, args.port, args.key, pwd, spwd, args.accept_new_hostkey, passphrase=kpwd)

    def confirm(msg):
        return args.yes or input(f"{msg} [yes/no] ").strip().lower() in ("yes", "y")

    if args.recover:
        try:
            return 0 if recover(rem, confirm) else 1
        except Exception as exc:
            print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 2
    what = ("nothing will be installed (--no-install); Lynis will be copied temporarily unless --skip lynis"
            if args.no_install else
            "ClamAV, chkrootkit and smartmontools will be installed and then removed (unless excluded with --skip) "
            "and Lynis will be copied temporarily")
    if not confirm(f"Assessment of {'this machine' if args.local else args.host}: {what}.\n"
                   "Do you have the system owner's authorisation?"):
        print("Aborted.")
        return 1

    opts = Options(nmap_ports=args.nmap_ports, clamav_full=args.clamav_full, clamav_quick=args.clamav_quick,
                   keep_tools=args.keep_tools, no_install=args.no_install, skip=set(args.skip), scan_timeout=args.scan_timeout * 60,
                   nse=not args.no_nse, nse_tls=args.nse_tls, lynis_dir=args.lynis_dir, local=args.local,
                   dns_zones=[z.rstrip(".") for z in args.dns_zone])
    try:
        rep = assess(rem, opts, args.out_dir)
    except KeyboardInterrupt:
        print("\nInterrupted by the user (cleanup already done). If needed: --recover.")
        return 130
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    if result is not None:
        result["report"] = rep
    print_summary(rep)
    return 0


def _recon(args, result=None) -> int:
    """--recon-only: no login. The login options are not needed and are ignored (no password is asked)."""
    unused = [o for o, v in (("-u", args.user), ("-i", args.key), ("--ask-pass", args.ask_pass),
                             ("--ask-key-pass", args.ask_key_pass), ("--ask-sudo-pass", args.ask_sudo_pass)) if v]
    if unused:
        print(f"Note: {', '.join(unused)} not used: --recon-only does not log in.")
    if not (args.yes or input(f"External reconnaissance of {args.host}: network probes from this machine only (nmap, "
                              "ssh-audit, DNS and MySQL probes); nothing is installed, run or written on the target, "
                              "but the probes are still a scan.\nDo you have the system owner's authorisation? "
                              "[yes/no] ").strip().lower() in ("yes", "y")):
        print("Aborted.")
        return 1
    opts = Options(nmap_ports=args.nmap_ports, skip=set(args.skip), scan_timeout=args.scan_timeout * 60,
                   nse=not args.no_nse, nse_tls=args.nse_tls, recon_only=True,
                   dns_zones=[z.rstrip(".") for z in args.dns_zone])
    try:
        rep = recon(NoLogin(args.host, args.port), opts, args.out_dir)
    except KeyboardInterrupt:
        print("\nInterrupted by the user.")
        return 130
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    if result is not None:
        result["report"] = rep
    print_summary(rep)
    return 0


def print_summary(rep: dict, top: int = 10):
    s = rep["summary"]
    print(f"\nOverall risk: {s['level']}  ("
          + ", ".join(f"{n} {lv.lower()}" for lv, n in s["counts"].items()) + ")")
    rows = rep["risks"][:top]
    if rows:
        print(f"\n{'ID':4} {'R':>3} {'I×L':5} {'Level':9} Problem")
        for r in rows:
            print(f"{r['id']:4} {r['risk']:>3} {r['impact']}×{r['probability']}   {r['level']:9} {r['title'][:90]}")
        if len(rep["risks"]) > top:
            print(f"... and {len(rep['risks']) - top} more in the report.")
    p = rep["paths"]
    print(f"\nReport (open in a browser):  {p.get('html', '-')}")
    print(f"   open it with:  xdg-open '{p.get('html', '')}'")
    print(f"Other formats:  {p['md']}\n                {p['json']}")
    if p.get("pdf"):
        print(f"                {p['pdf']}")
    elif p.get("dir"):
        print("                (no PDF: ReportLab is not installed; .venv/bin/pip install reportlab, then zsra-pdf DIR)")
    if p.get("dir"):
        print("\nThis report is a plaintext DRAFT, on this machine only. After reviewing it, to deliver it:\n"
              f"   zsra-finalize '{p['dir']}' --recipient RECIPIENT_PUBLIC_KEY --sign-key ~/.ssh/id_ed25519\n"
              "   (--omit F012 --reason '...' removes a detail too sensitive to circulate)")
