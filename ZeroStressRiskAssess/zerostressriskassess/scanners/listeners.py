"""Listening ports mapped to the process and program that opened them.

nmap sees WHAT answers from outside ("port 31337 with a web server") but not WHO keeps it open. From
inside, `ss -p` gives the process; from there the executable (`/proc/PID/exe`) is resolved and checked
against the distribution packages. A network listener whose program belongs to no package, lives in
/tmp or is an interpreter (python, perl, nc...) fits the profile of a backdoor.
"""
from __future__ import annotations

import os
import re

from ..models import ScanResult
from ..pkgowner import owned
from ..validate import only_pids, valid_path

USERS_RE = re.compile(r'\("([^"]+)",pid=(\d+),fd=\d+\)')
UID_RE = re.compile(r"\buid:(\d+)")   # from `ss -e`: available even when the process is NOT visible
TMP_RE = re.compile(r"^/(tmp|dev/shm|var/tmp)/")
# Programs that execute other code: listening on the network they are almost always anomalous.
INTERPRETERS = re.compile(r"^(python[0-9.]*|perl|ruby|node(js)?|php[0-9.]*|lua|bash|dash|sh|zsh|nc|ncat|netcat|socat)$")
SNAP_PREFIXES = ("/snap/", "/var/lib/snapd/")  # snap-managed services: not in dpkg, but managed

# For each PID: owner, executable, command line (truncated). All with the trusted PATH.
PID_SCRIPT = r"""
for p in @PIDS@; do
  [ -d /proc/$p ] || continue
  exe=$(readlink /proc/$p/exe 2>/dev/null)
  usr=$(stat -c %U /proc/$p 2>/dev/null)
  cmd=$(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null | head -c 200)
  echo "PID|$p|$usr|$exe|$cmd"
done
"""


def parse_ss(text: str):
    """From `ss -tulpn` -> [{proto, addr, port, loopback, procs:[(name,pid)]}]. Pure function."""
    out = []
    for line in text.splitlines():
        t = line.split()
        if len(t) < 6 or t[0] not in ("tcp", "udp") or t[1] not in ("LISTEN", "UNCONN"):
            continue
        addr, _, port = t[4].rpartition(":")
        if not port.isdigit():
            continue
        host = addr.strip("[]")
        loop = host.startswith("127.") or host == "::1" or host.endswith("%lo") or host == "localhost"
        out.append({"proto": t[0], "addr": host, "port": int(port), "loopback": loop,
                    "procs": [(n, int(p)) for n, p in USERS_RE.findall(line)],
                    "uid": int(m.group(1)) if (m := UID_RE.search(line)) else 0})   # ss omits uid:0
    return out


def script_of(cmd: str):
    """From 'python3 /usr/bin/wsdd --opt' extract the script being run ('/usr/bin/wsdd').
    None if the code does not come from a file: '-m module' or '-c "code"' (such as http.server).
    """
    tok = cmd.split()
    for idx, t in enumerate(tok):
        if INTERPRETERS.match(os.path.basename(t)):
            for a in tok[idx + 1:]:
                if a in ("-m", "-c", "-e", "-r"):
                    return None
                if a.startswith("-"):
                    continue
                return a if a.startswith("/") else None
            return None
    return None


def _judge(ctx, exe, exe_raw, cmd, loopback, is_owned):
    """(severity, title) for a listening process, or None if it is expected."""
    base = os.path.basename(exe)
    where = "locally" if loopback else "on the network"
    if TMP_RE.match(exe) or exe_raw.endswith("(deleted)"):
        return "critical", "Program in a temporary directory, or deleted, listening"
    if INTERPRETERS.match(base):
        script = script_of(cmd)
        if script and valid_path(script) and is_owned(script):
            # Script installed by a package (e.g. GNOME's wsdd for Windows networks): expected.
            return ("info" if loopback else "low"), f"Packaged script {os.path.basename(script)} listening {where}"
        return ("medium" if loopback else "high"), f"Interpreter ({base}) listening {where} with non-packaged code"
    if exe and not exe.startswith(SNAP_PREFIXES) and not is_owned(exe):
        return ("low" if loopback else "high"), f"Program outside packages listening {where}"
    return None


def run(ctx) -> ScanResult:
    res, rem = ScanResult("listeners"), ctx.rem
    r = rem.run("ss -tulpne 2>/dev/null", sudo=True)
    socks = parse_ss(r.out)
    if not socks:
        return res.skip("No listening sockets read (ss not available?)")

    pids = sorted({str(p) for s in socks for _, p in s["procs"]})
    pids = only_pids(pids)  # they end up in a command executed as root
    info = {}
    if pids:
        out = rem.run(PID_SCRIPT.replace("@PIDS@", " ".join(pids)), sudo=True).out
        for line in out.splitlines():
            parts = line.split("|", 4)
            if len(parts) == 5 and parts[0] == "PID" and parts[1].isdigit():
                info[int(parts[1])] = {"user": parts[2], "exe": parts[3], "cmd": parts[4].strip()}

    owned_cache = {}

    def is_owned(exe):
        if exe not in owned_cache:
            owned_cache[exe] = bool(valid_path(exe)) and owned(ctx, exe)
        return owned_cache[exe]

    exposed_list, table, seen, hidden = [], [], set(), {}
    groups = {}  # (pid, severity, title) -> [ports]: the same process on 7 ports is ONE finding
    for s in socks:
        label = f"{s['port']}/{s['proto']}"
        where = "local only" if s["loopback"] else f"on {s['addr']}"
        if not s["procs"]:
            if not s["loopback"]:
                # A multi-threaded service opens one socket per thread (BIND on 20 cores: 40 sockets on port 53).
                # One line per port and address, not one per socket.
                hidden.setdefault((label, s["addr"]), set()).add(s["uid"])
            continue
        for name, pid in s["procs"]:
            key = (label, pid, s["loopback"])
            if key in seen:
                continue
            seen.add(key)
            i = info.get(pid)
            if not i:
                continue
            exe_raw, exe = i["exe"], i["exe"].replace(" (deleted)", "")
            table.append({"port": label, "addr": s["addr"], "pid": pid, "process": name,
                          "exe": exe, "user": i["user"], "loopback": s["loopback"]})
            if not s["loopback"]:
                exposed_list.append(f"{label} {name}")
            verdict = _judge(ctx, exe, exe_raw, i["cmd"], s["loopback"], is_owned)
            if verdict:
                sev, title = verdict
                groups.setdefault((pid, sev, title), {"ports": [], "detail": i})["ports"].append(f"{label} ({where})")

    for (pid, sev, title), g in groups.items():
        i = g["detail"]
        res.add(sev, f"{title}: ports {', '.join(g['ports'][:8])}" + (" ..." if len(g["ports"]) > 8 else ""),
                f"{i['exe'] or '?'} (PID {pid}, user {i['user']}) command: {i['cmd']}")

    if hidden:
        # The PROCESS is not visible (container without CAP_SYS_PTRACE, /proc with hidepid), but the socket
        # OWNER is (uid: from `ss -e`): `ps` shows what runs under that user.
        # Verified with named as 'bind' and mariadbd as 'mysql' (uid:106) under capsh --drop=cap_sys_ptrace.
        owners = {}
        for line in rem.run("ps -eo uid=,user=,comm=", sudo=True).out.splitlines():
            p = line.split(None, 2)
            if len(p) == 3 and p[0].isdigit():
                owners.setdefault(int(p[0]), [p[1], set()])[1].add(p[2].strip())
        by_port = {}
        for (label, addr), uids in hidden.items():
            by_port.setdefault(label, [set(), set()])
            by_port[label][0].add(addr)
            by_port[label][1] |= uids
        parts = []
        for label, (addrs, uids) in sorted(by_port.items()):
            who = [f"user {owners[u][0]} ({', '.join(sorted(owners[u][1])[:4])})" if u in owners else f"uid {u}"
                   for u in sorted(uids)]
            parts.append(f"{label} on {', '.join(sorted(addrs))}: {'; '.join(who)}")
        res.add("low", "Listening ports with a process that is not visible: " + ", ".join(sorted(by_port)),
                " | ".join(parts) + ". The process is inferred from the socket owner: `ss` does not show it "
                "even with sudo (container without CAP_SYS_PTRACE or /proc mounted with hidepid).")
    res.data["listeners"] = table
    if exposed_list:
        res.add("info", "Listening on the network: " + ", ".join(sorted(set(exposed_list))))
    else:
        res.add("info", "No service listening on non-local addresses")
    return res
