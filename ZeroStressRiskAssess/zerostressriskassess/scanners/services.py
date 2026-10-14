"""Detection of suspicious (potentially malicious) systemd services.

There is no reliable way to state "this service is malware": heuristics based on typical signs of
malicious persistence are used (an attacker who wants to survive a reboot often creates a systemd
unit). Every signal is an INDICATOR to be verified manually, not a verdict, hence findings with a
severity.

`check_units` is a separate function because persistence.py reuses it (for services activated by
systemd timers).
"""
from __future__ import annotations

import re
import shlex

from ..models import ScanResult
from ..pkgowner import owned
from ..validate import valid_path

SUSPICIOUS = [
    (re.compile(r"(/tmp/|/dev/shm/|/var/tmp/)"), "high", "executable in a temporary directory"),
    (re.compile(r"(curl|wget)[^|;]*\|\s*(ba|z)?sh"), "critical", "downloads and executes remote code (pipe to shell)"),
    (re.compile(r"\bnc(at)?\b.*\s-e\b|/dev/tcp/|bash\s+-i"), "critical", "possible reverse shell"),
    (re.compile(r"base64\s+-d"), "high", "base64-encoded payload"),
    (re.compile(r"-m\s+(http\.server|SimpleHTTPServer)"), "high",
     "Python development web server as a service: publishes a directory without authentication"),
    (re.compile(r"\bnc(at)?\b.*\s-\w*l|socat\b.*(exec:|system:|tcp-listen)", re.I), "critical",
     "network listener with nc/socat (possible backdoor)"),
    (re.compile(r"\b(python[0-9.]*|perl|ruby|php|node)\s+-(c|e|r)\b"), "medium",
     "interpreter with code written inline in the command"),
    (re.compile(r"xmrig|minerd|kdevtmpfsi|kinsing|cpuminer", re.I), "critical", "typical cryptominer name"),
    (re.compile(r"/\.[A-Za-z0-9_][^/\s]*"), "medium", "path with hidden files/directories"),
]
# Without the last signal (hidden paths): in user configuration files (.bashrc, crontab)
# dot paths (~/.cargo, ~/.local) are perfectly normal.
SUSPICIOUS_STRONG = SUSPICIOUS[:-1]

STANDARD_DIRS = ("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/lib", "/lib", "/usr/libexec")
UNIT_RE = re.compile(r"[A-Za-z0-9:_.@\\-]+\.service")  # allow-list: the names come from the target


def check_units(ctx, res: ScanResult, units, origin: str = "Service") -> int:
    """Inspect the ExecStart of each unit and add findings to `res`. Returns how many units were inspected."""
    rem = ctx.rem
    units = sorted({u for u in units if UNIT_RE.fullmatch(u) and not u.endswith("@.service")})
    for i in range(0, len(units), 40):  # in chunks, to stay below the maximum command length
        chunk = units[i:i + 40]
        out = rem.run("systemctl show --no-pager -p Id -p FragmentPath -p ExecStart " +
                      " ".join(shlex.quote(u) for u in chunk)).out
        for block in out.split("\n\n"):
            kv = {}
            for line in block.splitlines():
                k, _, v = line.partition("=")
                kv[k] = v
            unit, frag, execstart = kv.get("Id", "?"), kv.get("FragmentPath", ""), kv.get("ExecStart", "")
            for rx, sev, why in SUSPICIOUS:
                if rx.search(execstart):
                    res.add(sev, f"{origin} {unit}: {why}", f"{frag}\n{execstart[:300]}")
            m = re.search(r"path=(\S+)", execstart)
            if m and not m.group(1).startswith(STANDARD_DIRS) and not owned(ctx, m.group(1)):
                # An unpackaged binary launched by a unit that DOES belong to a package is typical of programs
                # generated at boot (e.g. virtualisation platform agents in /run). It remains visible but weighs
                # less than an unknown unit.
                if valid_path(frag) and owned(ctx, frag):
                    res.add("low", f"{origin} {unit}: binary outside packages, but the unit is installed by a package",
                            f"binary {m.group(1)}; unit {frag}")
                else:
                    res.add("medium", f"{origin} {unit}: binary not owned by any package",
                            f"binary {m.group(1)}; unit {frag or '?'} (also outside packages)")
    return len(units)


def run(ctx) -> ScanResult:
    res, rem = ScanResult("services"), ctx.rem
    if rem.run("command -v systemctl").rc != 0:
        return res.skip("systemd not present: service check not performed")

    # Union of services running now and services enabled at boot.
    units = rem.run(
        "(systemctl list-units --type=service --state=running --no-legend --plain --no-pager;"
        " systemctl list-unit-files --type=service --state=enabled --no-legend --plain --no-pager)"
        " | awk '{print $1}' | sort -u").out.split()
    res.data["units_checked"] = check_units(ctx, res, units)

    # Internal view of listening ports, to be compared with what nmap saw.
    # A port listening inside but invisible outside is normal (firewall); the opposite is not.
    listen = rem.run("ss -tulpn 2>/dev/null | head -60", sudo=True).out
    res.data["listening"] = listen
    return res
