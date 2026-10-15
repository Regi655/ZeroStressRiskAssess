"""Tampering checks on common commands and processes (PIDs).

A typical user-mode rootkit replaces commands such as ls, ps, netstat and ss with modified versions
that hide the attacker's files, processes and connections. Four independent checks are performed, so
that if one is deceived the others can still detect the anomaly:

 1. Do the binaries belong to a distribution package? An `ls` owned by no package (e.g. in
    /usr/local/bin) is suspicious.
 2. Does the file hash match the package checksum? (`dpkg -V` compares the file on disk with the
    checksums recorded by the package.)
 3. Hidden PIDs: the process list in /proc (kernel) is compared with what `ps` shows. A PID present in
    /proc but missing from `ps` suggests a tampered `ps` (or a kernel rootkit).
 4. Processes whose executable lives in /tmp, /dev/shm or /var/tmp, or has been deleted from disk:
    typical of malware that removes itself after starting.
"""
from __future__ import annotations

import re
import shlex

from ..models import ScanResult
from ..ssh_client import TRUSTED_PATH
from ..pkgowner import owned, path_variants
from ..validate import is_pid, only_pids, split_pkgs, valid_path

COMMANDS = ("ls ps top netstat ss lsof find ip ifconfig who w last lastlog id sudo su login "
            "passwd sshd ssh cat grep stat pgrep crontab bash sh systemctl journalctl").split()

# For each command: path, real path (after symlinks), owner|mode, package.
# Runs with the "normal" PATH (trusted_path=False) only to detect whether something shadows the
# system command; the trusted PATH is used for everything else.
SCRIPT = r"""
NP=$PATH
export PATH=@TRUSTED@
for c in @CMDS@; do
  sysp=$(command -v "$c" 2>/dev/null)                 # the system command (trusted PATH)
  usr=$(PATH=$NP command -v "$c" 2>/dev/null)         # what a user would execute
  case "$usr" in /*) if [ -n "$sysp" ] && [ "$(readlink -f "$usr")" != "$(readlink -f "$sysp")" ]; then
      echo "SHADOW|$c|$usr|$sysp|$(stat -c '%U|%a' "$usr" 2>/dev/null)"; fi;; esac
  p=${sysp:-$usr}
  case "$p" in /*) ;; *) continue;; esac
  r=$(readlink -f "$p")
  meta=$(stat -c '%U|%a' "$r" 2>/dev/null)
  # Paths to try: the real one, the one in PATH and the forms without /usr
  # (the package database records /bin/ls, not /usr/bin/ls: see pkgowner.py).
  alts=""
  for q in "$r" "$p"; do
    case "$q" in /usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/lib64/*) alts="$alts ${q#/usr}";; esac
  done
  pkg=""
  for q in "$r" "$p" $alts; do
    if out=$(dpkg -S "$q" 2>/dev/null); then pkg=$(echo "$out" | head -1 | cut -d: -f1); fi
    [ -n "$pkg" ] && break
  done
  echo "CMD|$c|$p|$r|$meta|$pkg"
done
"""

EXE_SCRIPT = r"""
for p in /proc/[0-9]*; do
  e=$(readlink "$p/exe" 2>/dev/null)
  [ -n "$e" ] && echo "${p#/proc/}|$e"
done
"""

TMP_RE = re.compile(r"^/(tmp|dev/shm|var/tmp)/")


def run(ctx) -> ScanResult:
    res, rem = ScanResult("integrity"), ctx.rem

    # ---- 1) ownership and permissions of the binaries
    script = SCRIPT.replace("@CMDS@", " ".join(COMMANDS)).replace("@TRUSTED@", TRUSTED_PATH)
    out = rem.run(script, sudo=True, trusted_path=False).out
    infos = []
    for line in out.splitlines():
        if line.startswith("SHADOW|"):
            # A file earlier in the PATH than the system one: a classic user-mode rootkit disguise
            # (or, more mundanely, an administrator's wrapper: to be verified).
            sp = line.split("|") + [""] * 6
            _, cmd, fake, real_sys, sh_owner, sh_mode = sp[:6]
            sev = "critical" if TMP_RE.match(fake) else "high"
            res.add(sev, f"'{cmd}' is shadowed by another file in PATH",
                    f"{fake} (owner {sh_owner}, mode {sh_mode}) is executed instead of {real_sys}. "
                    "The tool does NOT run it: it always uses the system command.")
            continue
        if not line.startswith("CMD|"):
            continue
        parts = line.split("|")
        parts += [""] * (7 - len(parts))  # fields are missing if stat failed
        _, cmd, path, real, owner, mode, pkg = parts[:7]
        infos.append({"cmd": cmd, "path": path, "real": real, "owner": owner, "mode": mode, "pkg": pkg})

        if TMP_RE.match(real):
            res.add("critical", f"'{cmd}' resolves to a temporary directory", real)
        if owner and owner != "root":
            res.add("high", f"'{cmd}' is not owned by root", f"{real} owner={owner}")
        if mode and mode[-1] in "2367":
            res.add("high", f"'{cmd}' is writable by everyone", f"{real} mode={mode}")
        if not pkg:
            res.add("medium", f"'{cmd}' does not belong to any package",
                    f"{real} (may be legitimate, e.g. a manual build; verify)")
    res.data["checked_commands"] = len(infos)

    # ---- 2) checksum against the package
    pkgs, bad_pkgs = split_pkgs({i["pkg"] for i in infos if i["pkg"]})
    for b in bad_pkgs:  # an implausible package name is suspicious in itself
        res.add("high", "Anomalous package name returned by the target", b[:80])
    # dpkg -V prints the path as recorded by the package (/bin/ls): all forms are tracked,
    # otherwise a modified binary could go unnoticed.
    watched = set()
    for i in infos:
        watched.update(path_variants(i["path"]))
        watched.update(path_variants(i["real"]))
    if pkgs:
        v = rem.run("dpkg -V " + " ".join(shlex.quote(p) for p in pkgs), sudo=True, timeout=900).out
        for line in v.splitlines():
            tok = line.split()
            if len(tok) < 2 or tok[-1] not in watched:
                continue  # modified configuration files are expected and ignored
            flags, path = tok[0], tok[-1]
            if len(flags) > 2 and flags[2] == "5":
                res.add("critical", "Binary hash differs from the package", f"{path} [{flags}]")
            else:
                res.add("high", "Binary modified compared to the package", f"{path} [{flags}]")
    else:
        res.add("info", "No package associated with the commands: checksum verification not performed")

    # ---- 3) hidden PIDs: /proc (kernel) versus ps (userland)
    in_proc = set(only_pids(rem.run("ls /proc | grep -E '^[0-9]+$'", sudo=True).out.split()))
    ps_tokens = rem.run("ps -e -o pid=", sudo=True).out.split()
    in_ps = set(only_pids(ps_tokens))
    # `ps -e -o pid=` prints ONLY numbers: anything else is tampered output.
    weird = [t for t in ps_tokens if not is_pid(t)]
    if weird:
        res.add("high", "ps returned non-numeric output", repr(weird[:5]))

    def still_alive(pids):
        # Very short-lived processes (our own commands) appear in one list and not in the other:
        # they are re-checked after a moment to discard these false positives.
        pids = only_pids(pids)  # defence in depth: they end up in a command executed as root
        if not pids:
            return []
        chk = " ".join(sorted(pids))
        return rem.run(f"sleep 1; for p in {chk}; do [ -d /proc/$p ] && echo $p; done", sudo=True).out.split()

    for pid in still_alive(in_proc - in_ps):
        res.add("critical", f"PID {pid} present in /proc but NOT shown by ps",
                "possibly a tampered `ps` or a rootkit hiding processes")
    # The PID of the `ps` command itself appears only in its own output: it is discarded by
    # re-checking that the process still exists (if it disappeared it was transient).
    ps_only = set(still_alive(in_ps - in_proc))
    if ps_only:
        res.add("medium", "ps shows PIDs that /proc does not list", ",".join(sorted(ps_only)))

    # ---- 4) suspicious executables of running processes
    deleted = {}
    for line in rem.run(EXE_SCRIPT, sudo=True).out.splitlines():
        pid, _, exe = line.partition("|")
        if TMP_RE.match(exe.replace(" (deleted)", "")):
            res.add("high", f"Process {pid} executed from a temporary directory", exe)
        elif exe.endswith("(deleted)"):
            deleted.setdefault(exe[:-len(" (deleted)")], []).append(pid)
    restart = []
    for exe, pids in deleted.items():
        # Common case: the program was UPGRADED (old file replaced) while the process still runs the
        # old version. If a packaged file is now in its place, a restart is enough. A deleted executable
        # that was not replaced remains suspicious.
        if valid_path(exe) and owned(ctx, exe):
            restart.append(f"{exe} (PID {', '.join(pids[:5])})")
        else:
            res.add("medium", f"Process with executable deleted from disk and not replaced: {exe}",
                    "PID " + ", ".join(pids[:10]) + ". Typical of malware that deletes itself after starting.")
    if restart:
        res.add("low", f"{len(restart)} updated programs still running the old version",
                "Restart the processes (or the machine) to use the fixed version: " + "; ".join(restart))
    res.data["procs_proc"], res.data["procs_ps"] = len(in_proc), len(in_ps)
    return res
