"""sudo configuration checks.

/etc/sudoers decides who can become root and how. A single line such as
"user ALL=(ALL) NOPASSWD: ALL" grants full privileges without a password, and allowing through sudo a
program able to spawn a shell (vim, find, less...) is equivalent to granting root even when the rule
looks restricted ("shell escape"). Findings are INDICATORS: many configurations are intended and
legitimate.
"""
from __future__ import annotations

import os
import re

from ..models import ScanResult

EXPECTED_WHO = {"root", "%sudo", "%admin", "%wheel"}
# Programs that, run as root, allow executing other commands (shell escape).
SHELL_ESCAPE = {"vi", "vim", "view", "nano", "less", "more", "man", "find", "awk", "gawk", "python", "python3",
                "perl", "ruby", "lua", "bash", "sh", "dash", "zsh", "env", "tar", "zip", "nmap", "git", "ftp",
                "ssh", "rsync", "docker", "mount", "journalctl", "systemctl", "apt", "apt-get", "pip", "pip3",
                "npm", "busybox", "expect", "openssl"}
# Programs that allow writing arbitrary files as root.
FILE_WRITE = {"cp", "mv", "chmod", "chown", "dd", "tee", "sed", "wget", "curl"}

SCRIPT = r"""
for f in /etc/sudoers /etc/sudoers.d/*; do
  b=${f##*/}
  case "$b" in *.*|*~) continue;; esac   # sudo ignora questi nomi
  [ -f "$f" ] || continue
  echo "### FILE $f"
  cat "$f"
done
"""


def _logical_lines(lines):
    """Join lines ending with a backslash (continuation) and drop comments and empty lines."""
    buf = ""
    for raw in lines:
        line = raw.rstrip()
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        line = (buf + line).strip()
        buf = ""
        if line and (not line.startswith("#") or line.startswith(("#include", "#includedir"))):
            yield line


TAG_RE = re.compile(r"^(?:(?:NO)?(?:PASSWD|EXEC|SETENV|LOG_INPUT|LOG_OUTPUT|MAIL|FOLLOW|INTERCEPT)\s*:\s*)+")


def commands_of(right: str):
    """Commands of a rule: [(path, arguments)]. Pure function.

    In sudoers a command written WITHOUT arguments can be run with ANY arguments; to forbid them
    an empty argument list must be written explicitly (/usr/sbin/reboot ""). With
    "(root) NOPASSWD: /usr/sbin/lynis" the user can therefore pass any option to lynis, including
    those that read files or load plugins.
    """
    out = []
    for part in re.split(r"(?<!\\),", right):
        part = re.sub(r"^\s*\([^)]*\)\s*", "", part.strip())   # (root) / (ALL:ALL)
        part = TAG_RE.sub("", part).strip()
        if not part or part == "ALL" or part.startswith("!"):
            continue
        tok = part.split(None, 1)
        out.append((tok[0], tok[1].strip() if len(tok) > 1 else None))
    return out


def _check_rule(res, src, who, right, aliases):
    expanded = right
    for name, val in aliases.items():
        if re.search(rf"\b{re.escape(name)}\b", right):
            expanded += " " + val
    shown = f"{src}: {who} = {right[:200]}"
    grants_all = bool(re.search(r"(\)|:|=)\s*ALL\s*(,|$)", "=" + right))

    if "NOPASSWD" in right:
        full = bool(re.search(r"NOPASSWD:\s*(?:\([^)]*\)\s*)?ALL\b", right))
        res.add("high" if full else "medium",
                "Passwordless sudo rule" + (" for ALL commands" if full else ""), shown)
    if who == "ALL" and grants_all:
        res.add("critical", "Any user can run any command with sudo", shown)
    elif grants_all and who not in EXPECTED_WHO:
        res.add("medium", f"'{who}' can run any command as root", shown)

    names = {os.path.basename(t) for t in re.findall(r"[/\w.+-]+", expanded)}
    esc = sorted(names & SHELL_ESCAPE)
    if esc and not grants_all:
        res.add("high", f"sudo rule with programs that allow spawning a shell: {', '.join(esc)}", shown)
    wr = sorted(names & FILE_WRITE)
    if wr and not grants_all:
        res.add("medium", f"sudo rule with programs that write arbitrary files: {', '.join(wr)}", shown)
    if "*" in right and not grants_all:
        res.add("medium", "sudo rule with a wildcard (*): allows unexpected arguments", shown)
    if not grants_all:
        free = [c for c, a in commands_of(right) if c.startswith("/") and a is None
                and os.path.basename(c) not in SHELL_ESCAPE]   # shell-escape programs are already "high"
        if free:
            res.add("medium" if "NOPASSWD" in right else "low",
                    "sudo rule without argument restrictions: " + ", ".join(free),
                    shown + " | Without arguments in the rule, sudo accepts ANY option. Specify the "
                    "allowed arguments (or \"\" for none) and check that the program has no options that "
                    "read files or load code.")


def _check_defaults(res, src, line):
    if re.search(r"!\s*authenticate", line):
        res.add("high", "Defaults !authenticate: sudo never asks for a password", f"{src}: {line[:200]}")
    if re.search(r"!\s*env_reset", line):
        res.add("high", "Defaults !env_reset: the user's environment variables are passed to sudo", f"{src}: {line[:200]}")
    if re.search(r"env_keep.*(LD_PRELOAD|LD_LIBRARY_PATH)", line):
        res.add("high", "Defaults keeps LD_PRELOAD/LD_LIBRARY_PATH: privilege escalation", f"{src}: {line[:200]}")
    if re.search(r"timestamp_timeout\s*=\s*-1", line):
        res.add("medium", "The sudo password never expires (timestamp_timeout=-1)", f"{src}: {line[:200]}")
    if re.search(r"(?<!!)\bsetenv\b", line):
        res.add("medium", "Defaults setenv: the user can set environment variables for commands", f"{src}: {line[:200]}")


def _check_targets(res, rem, files, aliases):
    """Programs allowed through sudo must be modifiable ONLY by root: if a user can rewrite
    /opt/tools/backup.sh and that script is in sudoers, that user becomes root.
    Both the file and its directory are checked (whoever writes to the directory can replace the file).
    """
    paths = set()
    for lines in files.values():
        for line in _logical_lines(lines):
            m = re.match(r"(?:Cmnd_Alias\s+\w+|\S+\s+.+?)\s*=\s*(.*)", line)
            if m and not line.startswith(("Defaults", "#")):
                paths.update(c for c, _ in commands_of(m.group(1)) if re.fullmatch(r"/[\w./+-]+", c))
    if not paths:
        return
    q = " ".join(sorted(paths | {os.path.dirname(p) for p in paths}))
    st = rem.run(f"stat -L -c '%a|%u|%n' {q} 2>/dev/null", sudo=True).out
    for line in st.splitlines():
        mode, uid, path = (line.split("|", 2) + ["", ""])[:3]
        if not mode.isdigit():
            continue
        m = int(mode, 8)
        if uid != "0" or m & 0o022:
            kind = "program directory" if path not in paths else "program"
            res.add("critical", f"sudo: {kind} modifiable by non-root users: {path}",
                    f"mode={mode} uid={uid}. Whoever can modify it runs code as root.")


def run(ctx) -> ScanResult:
    res, rem = ScanResult("sudoers"), ctx.rem
    out = rem.run(SCRIPT, sudo=True).out
    if "### FILE" not in out:
        return res.skip("No readable sudoers file (sudo not installed or access denied)")

    files, cur = {}, None
    for line in out.splitlines():
        if line.startswith("### FILE "):
            cur = line[9:]
            files[cur] = []
        elif cur:
            files[cur].append(line)

    aliases, nrules = {}, 0
    for src, lines in files.items():
        for line in _logical_lines(lines):
            if line.startswith("#"):
                continue  # #include / #includedir
            m_alias = re.match(r"(Cmnd_Alias)\s+(\w+)\s*=\s*(.*)", line)
            if m_alias:
                aliases[m_alias.group(2)] = m_alias.group(3)
                continue
            if re.match(r"(User_Alias|Host_Alias|Runas_Alias)\b", line):
                continue
            if line.startswith("Defaults"):
                _check_defaults(res, src, line)
                continue
            m = re.match(r"(\S+)\s+(.+?)\s*=\s*(.*)", line)
            if m:
                nrules += 1
                _check_rule(res, src, m.group(1), m.group(3), aliases)
    res.data["rules_checked"] = nrules
    _check_targets(res, rem, files, aliases)

    # Syntax: a broken sudoers file can lock out administrative access.
    if rem.run("command -v visudo").rc == 0:
        v = rem.run("visudo -c", sudo=True)
        if v.rc != 0:
            res.add("high", "visudo -c reports configuration errors", v.out[-400:])

    # Permissions: sudo requires root-owned files not writable by others (0440).
    st = rem.run("stat -c '%a|%U|%n' /etc/sudoers /etc/sudoers.d /etc/sudoers.d/* 2>/dev/null", sudo=True).out
    for line in st.splitlines():
        mode, _, rest = line.partition("|")
        owner, _, path = rest.partition("|")
        if not mode.isdigit():
            continue
        m = int(mode, 8)
        is_dir = path.rstrip("/") == "/etc/sudoers.d"
        if m & 0o022:
            res.add("critical", "sudoers file/directory writable by group or others", f"{path} mode={mode}")
        elif owner != "root":
            res.add("high", "sudoers file not owned by root", f"{path} owner={owner}")
        elif not is_dir and mode != "440":
            res.add("medium", "sudoers permissions differ from the expected 0440", f"{path} mode={mode}")

    for line in rem.run("getent group sudo wheel admin").out.splitlines():
        p = line.split(":")
        if len(p) >= 4:
            res.add("info", f"Members of group {p[0]}: {p[3] or 'none'}")
    return res
