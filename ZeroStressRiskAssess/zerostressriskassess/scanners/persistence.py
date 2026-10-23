"""Persistence: every way something can restart on its own (besides systemd services, covered by
services.py).

An attacker who gained access wants to regain it after a reboot or after the first backdoor is
discovered. The usual places are cron, systemd timers, startup scripts, shell profile files, libraries
force-loaded through ld.so.preload (a rootkit technique) and authorized SSH keys. Every finding is an
INDICATOR to be verified manually.
"""
from __future__ import annotations

import re
import shlex

from ..models import ScanResult
from ..validate import valid_path
from .accounts import NOLOGIN, get_users
from .services import SUSPICIOUS_STRONG, check_units

PROFILE_EXTRA = [
    (re.compile(r"\bLD_PRELOAD\s*="), "critical", "sets LD_PRELOAD (loads libraries into every program)"),
    # An alias such as  alias ls='ls --color=auto'  is normal: it is reported only if the replaced
    # command points to SOMETHING ELSE. The negative lookahead (?!...\1\b) excludes the "same command"
    # case (including /usr/bin/... paths); the quote is matched INSIDE the lookahead because, if it were
    # consumed outside, the engine would try the "without quote" variant.
    (re.compile(r"^\s*alias\s+(sudo|su|ssh|ls|ps|passwd|cat)=(?!['\"]?(?:/usr)?(?:/s?bin/)?\1\b)"),
     "high", "alias replacing a sensitive command with something else"),
]
TIMER_RE = re.compile(r"[A-Za-z0-9:_.@\\-]+\.timer")
UNIT_LINE = re.compile(r"Unit=([A-Za-z0-9:_.@\\-]+\.service)")


def _grep(rem, targets: str):
    """Active lines (not comments, not empty) of the given files: (path, line)."""
    out = rem.run(f"grep -HIsvE '^[[:space:]]*(#|$)' {targets} 2>/dev/null", sudo=True, timeout=300).out
    for l in out.splitlines():
        path, _, line = l.partition(":")
        yield path, line


def _flag(res, label, path, line, extra=()):
    for rx, sev, why in list(SUSPICIOUS_STRONG) + list(extra):
        if rx.search(line):
            res.add(sev, f"{label}: {why}", f"{path}: {line.strip()[:200]}")


def run(ctx) -> ScanResult:
    res, rem = ScanResult("persistence"), ctx.rem
    users, uid_min = get_users(ctx)

    # ---- cron: system and users
    cron_targets = ("/etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* "
                    "/etc/cron.monthly/* /var/spool/cron/crontabs/* /var/spool/cron/*")
    files = set()
    for path, line in _grep(rem, cron_targets):
        files.add(path)
        _flag(res, "Cron", path, line)
    res.data["cron_files_with_entries"] = len(files)
    # one `ls` per directory, no headers; -p appends "/" to subdirectories, which are discarded
    user_tabs = rem.run("for d in /var/spool/cron/crontabs /var/spool/cron; do [ -d \"$d\" ] && "
                        "ls -1p \"$d\" | grep -v '/$'; done", sudo=True).out.split()
    if user_tabs:
        res.add("info", "User crontabs present", ", ".join(sorted(set(user_tabs))[:20]))

    # ---- systemd timers -> the services they activate
    if rem.run("command -v systemctl").rc == 0:
        timers = [t for t in rem.run("systemctl list-unit-files --type=timer --state=enabled --no-legend "
                                     "--plain --no-pager | awk '{print $1}'").out.split() if TIMER_RE.fullmatch(t)]
        svc = set()
        for i in range(0, len(timers), 40):
            out = rem.run("systemctl show --no-pager -p Unit " + " ".join(shlex.quote(t) for t in timers[i:i + 40])).out
            svc.update(UNIT_LINE.findall(out))
        res.data["timers"] = len(timers)
        check_units(ctx, res, svc, origin="Timer, service")

    # ---- at (one-off scheduled jobs)
    if rem.run("command -v atq").rc == 0:
        for line in rem.run("atq", sudo=True).out.splitlines():
            res.add("low", "Scheduled 'at' job", line[:150])

    # ---- rc.local and init.d scripts not owned by packages
    for path, line in _grep(rem, "/etc/rc.local"):
        # "touch /var/lock/subsys/local" is the default content of rc.local on RHEL/Rocky.
        if line.strip() in ("exit 0", "touch /var/lock/subsys/local") or line.startswith("#!"):
            continue
        res.add("low", "rc.local contains commands", f"{path}: {line.strip()[:200]}")
        _flag(res, "rc.local", path, line)
    own = "dpkg -S" if ctx.osinfo.pkg_mgr == "apt" else "rpm -qf"
    unowned = rem.run(
        f"for f in /etc/init.d/*; do [ -f \"$f\" ] || continue; {own} \"$f\" >/dev/null 2>&1 || echo \"$f\"; done "
        "| head -60", sudo=True).out.split()
    for f in unowned:
        if not f.endswith(("/README", "/skeleton")):
            res.add("low", "init.d script not owned by any package", f)

    # ---- shell profile files (global and per user)
    homes = {}
    for u in users:
        if not u["bad"] and valid_path(u["home"]) and (u["shell"] not in NOLOGIN or u["uid"] == 0):
            homes[u["home"]] = u
    rc = ("/etc/profile /etc/bash.bashrc /etc/bashrc /etc/zsh/zshenv /etc/profile.d/* " +
          " ".join(shlex.quote(f"{h}/{f}") for h in homes
                   for f in (".bashrc", ".profile", ".bash_profile", ".bash_login", ".zshrc", ".bash_logout")))
    for path, line in _grep(rem, rc):
        _flag(res, "Shell profile file", path, line, extra=PROFILE_EXTRA)

    # ---- ld.so.preload: legitimately almost always absent
    for path, line in _grep(rem, "/etc/ld.so.preload"):
        res.add("critical", "/etc/ld.so.preload contains libraries loaded into every process",
                f"{path}: {line.strip()[:200]} (typical rootkit technique)")

    # ---- authorized SSH keys: a classic way to regain access without a password
    script = ('for h in ' + " ".join(shlex.quote(h) for h in homes) + '; do '
              'for f in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do '
              '[ -f "$f" ] && { echo "FILE|$f"; ssh-keygen -lf "$f" 2>/dev/null | sed "s/^/KEY|/"; '
              'echo "COUNT|$(grep -cvE \'^[[:space:]]*(#|$)\' "$f")"; }; done; done')
    if homes:
        cur, keys, counts = None, {}, {}
        for line in rem.run(script, sudo=True, timeout=120).out.splitlines():
            if line.startswith("FILE|"):
                cur = line[5:]
                keys[cur] = []
            elif line.startswith("KEY|") and cur and re.match(r"\d+ \S+:", line[4:]):
                keys[cur].append(line[4:])  # only lines that look like a key fingerprint
            elif line.startswith("COUNT|") and cur and line[6:].strip().isdigit():
                counts[cur] = int(line[6:])
        for path, ks in keys.items():
            home = path.rsplit("/.ssh/", 1)[0]
            u = homes.get(home, {})
            if counts.get(path, len(ks)) == 0:
                res.add("info", "authorized_keys file present but empty", path)
                continue
            summary = "; ".join(k[:110] for k in ks[:8])
            if u.get("name") == "root":
                sev, why = "medium", "authorized SSH keys for root"
            elif u.get("shell") in NOLOGIN or (u.get("uid", 9999) < uid_min and u.get("name") != "root"):
                sev, why = "high", f"authorized SSH keys for system account '{u.get('name')}'"
            else:
                sev, why = "info", f"authorized SSH keys for '{u.get('name', '?')}'"
            res.add(sev, f"{why} ({counts.get(path, len(ks))})", f"{path}: {summary}")
    return res
