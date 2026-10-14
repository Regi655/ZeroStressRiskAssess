"""Permissions of important files and directories.

Permissions are the first line of local defence. A world-writable /etc/passwd allows creating a root
user; an SSH private key readable by others allows impersonating its owner; a misplaced SUID file
(which runs with its owner's privileges, usually root) is a shortcut to root. A "maximum allowed
mode" criterion is applied: anything less permissive is acceptable, anything more permissive is
reported.
"""
from __future__ import annotations

import os
import re
import shlex

from ..models import ScanResult
from ..pkgowner import owned, verify_file
from ..validate import valid_path
from .accounts import NOLOGIN, get_users

# (path, maximum allowed mode). Any of these being world-writable is CRITICAL:
# it allows becoming root (adding a user, a cron job, a sudo rule...).
CHECKS = [
    ("/etc/passwd", 0o644), ("/etc/group", 0o644),
    ("/etc/shadow", 0o640), ("/etc/gshadow", 0o640),
    ("/etc/sudoers", 0o440), ("/etc/ssh/sshd_config", 0o644),
    ("/etc/crontab", 0o644), ("/etc", 0o755), ("/etc/ssh", 0o755),
    ("/etc/cron.d", 0o755), ("/root", 0o750), ("/etc/ssl/private", 0o750),
]
# They contain secrets (password hashes, private keys): world-READABLE is CRITICAL.
SECRET_PATHS = {"/etc/shadow", "/etc/gshadow", "/etc/ssl/private", "/root"}
# Directories where a world-writable file or directory is more severe than elsewhere.
SENSITIVE_PREFIXES = ("/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/root", "/opt",
                      "/srv", "/var/www", "/var/spool", "/var/lib", "/var/backups")
LOCK_RE = re.compile(r"(\.lock|\.lck|/LOCK)$")
SECRET_FILE_RE = re.compile(r"^(wp-config\.php|\.env(\..+)?|.+\.env|config\.php|settings\.py|local_settings\.py|\.htpasswd|"
                            r"credentials(\.json)?|.+\.(pem|key|p12|pfx|kdbx)|id_(rsa|dsa|ecdsa|ed25519))$")
# Names (and contents) of shells/interpreters: such a SUID binary is a direct path to root.
SHELL_NAMES = {"sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "ash", "fish", "python", "python2", "python3",
               "perl", "ruby", "node", "php", "lua", "awk", "gawk", "vi", "vim", "nano", "find", "nmap", "env",
               "less", "more", "cp", "tar", "zip", "docker"}
STICKY_DIRS = ["/tmp", "/var/tmp", "/dev/shm"]  # world-writable, BUT with the sticky bit
PRUNE = r"\( -path /var/lib/docker -o -path /var/lib/containerd -o -path /var/lib/containers -o -path /var/lib/rancher -o -path /var/lib/machines -o -path /snap -o -path /var/lib/snapd -o -path /var/lib/lxd -o -path /var/lib/kubelet \) -prune -o"
# Filesystems to search. "/" is ALWAYS included: in a container (or a live system) the root is an
# overlay filesystem and would not appear among the "real" ones, so the search would not run at all.
# With -xdev each find stays within its own filesystem, so adding "/" does not descend into /proc
# or network mounts.
MOUNTS = "$({ echo /; findmnt -rno TARGET -t ext2,ext3,ext4,xfs,btrfs; } 2>/dev/null | sort -u)"

# Names of SUID/SGID files normally found in a standard distribution.
KNOWN_SUID = {"passwd", "su", "sudo", "sudoedit", "mount", "umount", "chsh", "chfn", "gpasswd", "newgrp",
              "pkexec", "fusermount", "fusermount3", "ping", "ping6", "unix_chkpwd", "chage", "expiry",
              "ssh-keysign", "ssh-agent", "dbus-daemon-launch-helper", "polkit-agent-helper-1", "at",
              "crontab", "wall", "write", "bsd-write", "plocate", "mlocate", "locate", "mount.nfs", "mount.cifs",
              "newuidmap", "newgidmap", "dotlockfile", "pam_timestamp_check", "unix_update", "snap-confine",
              "utempter", "traceroute6.iputils", "Xorg.wrap", "ntfs-3g", "umount.nfs", "ssh-agent",
              "pam_extrausers_chkpwd", "userhelper",
              "auth_pam_tool"}   # PAM helper of the mariadb-server package
STD_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/")
BAD_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/", "/home/", "/run/", "/var/www/")


# ---- file capabilities (getcap)
# A capability grants a program PART of root's powers without SUID. Some are sufficient on their own
# to become root (verified: python3 with cap_setuid can call os.setuid(0) and become uid 0).
CAP_ROOT = {"cap_setuid", "cap_setgid", "cap_sys_admin", "cap_sys_ptrace", "cap_sys_module", "cap_dac_override",
            "cap_chown", "cap_fowner", "cap_setfcap", "cap_sys_rawio", "cap_bpf"}
CAP_READ_ALL = {"cap_dac_read_search"}      # reads any file, including /etc/shadow
CAP_NET = {"cap_net_admin"}                 # reconfigures the network (firewall, interfaces)
# System programs that NEED root capabilities to work, when installed by a package: reporting them
# as "medium" was noise (e.g. sssd helpers and snap-confine on a desktop Ubuntu). They remain visible
# in an info line; if they do NOT come from a package they are evaluated like any other program.
KNOWN_CAPS = {"krb5_child", "ldap_child", "selinux_child", "sssd_pam", "proxy_child", "gpo_child", "p11_child",
              "snap-confine", "newuidmap", "newgidmap", "dumpcap", "gst-ptp-helper", "ping", "mtr-packet",
              "arping", "clockdiff", "fping", "fping6", "traceroute6.iputils", "kismet_cap_linux_wifi"}
CAP_LINE_RE = re.compile(r"^(/\S+)\s+(?:=\s+)?(cap_[a-z_,+=]+.*)$")


def parse_getcap(text: str):
    """[(path, {capabilities})]. Supports libcap >= 2.4x ("/bin/x cap_a,cap_b=ep") and the older format
    ("/bin/x = cap_a+ep"). Pure function.
    """
    out = []
    for line in text.splitlines():
        m = CAP_LINE_RE.match(line.strip())
        if m:
            caps = set(re.findall(r"cap_[a-z_]+", m.group(2)))
            if caps:
                out.append((m.group(1), caps))
    return out


def _check_caps(ctx, res):
    rem = ctx.rem
    if rem.run("command -v getcap").rc != 0:
        res.add("info", "getcap not available: file capabilities not checked",
                "Package libcap2-bin (Debian/Ubuntu) or libcap (RHEL).")
        return
    out = rem.run(f"for m in {MOUNTS}; do nice -n 19 ionice -c3 find \"$m\" -xdev {PRUNE} -type f -perm /111 "
                  "-print0 2>/dev/null | xargs -0 -r getcap 2>/dev/null; done | head -200",
                  sudo=True, timeout=ctx.opts.scan_timeout).out
    found = parse_getcap(out)
    res.data["file_capabilities"] = len(found)
    known = []
    for path, caps in found:
        root, read, net = caps & CAP_ROOT, caps & CAP_READ_ALL, caps & CAP_NET
        packaged = valid_path(path) and owned(ctx, path)
        shown = f"{path}: {', '.join(sorted(caps))}"
        if packaged and path.rsplit("/", 1)[-1] in KNOWN_CAPS:
            pkg, intact = verify_file(ctx, path)
            if intact is False:
                res.add("critical", "Program with capability MODIFIED compared to its package",
                        f"{shown} (package {pkg}): the file does not match the package checksum.")
            else:
                known.append(path)
        elif (root or read) and _is_shell_copy(ctx, path):
            res.add("critical", "Interpreter or shell with a root capability: direct shortcut to root", shown)
        elif root:
            res.add("medium" if packaged else "high",
                    "Root-equivalent capability on a program" + ("" if packaged else " outside packages"),
                    shown + ". Whoever runs it (or replaces it, if it is not root-owned) gains root powers.")
        elif read:
            res.add("medium" if packaged else "high", "Capability that reads ANY file (cap_dac_read_search)",
                    shown + ". Sufficient to read /etc/shadow and private keys.")
        elif net and not packaged:
            res.add("medium", "cap_net_admin on a program outside packages", shown)
        elif not packaged:
            res.add("low", "Program outside packages with a capability", shown)
    if known:
        res.add("info", f"Capabilities on known system programs installed by packages ({len(known)})",
                ", ".join(known[:15]) + ". Required for them to work; each one matches its "
                "package checksum (dpkg -V / rpm -V).")


def _is_shell_copy(ctx, path: str) -> bool:
    """True if the file is named like a shell/interpreter or has the same content as a system one.
    The name alone can be faked (renaming the copy is enough), so the hash is compared as well.
    """
    # The name is split into words ("bash_suid" -> bash, suid) so that "cpulimit" is not mistaken for "cp".
    if SHELL_NAMES & set(re.split(r"[^a-z0-9]+", os.path.basename(path).lower())):
        return True
    cmd = ("h=$(sha256sum -- " + shlex.quote(path) + " | cut -d' ' -f1); [ -n \"$h\" ] || exit 1; "
           "for b in bash sh dash zsh ksh python3 perl ruby; do q=$(command -v $b) || continue; "
           "[ \"$(sha256sum -- \"$(readlink -f \"$q\")\" | cut -d' ' -f1)\" = \"$h\" ] && exit 0; done; exit 1")
    return ctx.rem.run(cmd, sudo=True).rc == 0


def _stat(rem, quoted_paths: str, glob: str = "", numeric: bool = False):
    """(mode, owner, group, path). numeric=True: UID/GID instead of names."""
    fmt = "%a|%u|%g|%n" if numeric else "%a|%U|%G|%n"
    out = rem.run(f"stat -c '{fmt}' {quoted_paths} {glob} 2>/dev/null", sudo=True).out
    for line in out.splitlines():
        p = line.split("|", 3)
        if len(p) == 4 and p[0].isdigit():
            yield int(p[0], 8), p[1], p[2], p[3]


def run(ctx) -> ScanResult:
    res, rem = ScanResult("permissions"), ctx.rem
    users, uid_min = get_users(ctx)
    max_by_path = dict(CHECKS)
    flagged_dirs = set()  # directories already reported above: not repeated as "without sticky bit"

    # ---- system files and directories
    paths = " ".join(shlex.quote(p) for p, _ in CHECKS)
    for mode, owner, group, path in _stat(rem, paths, "/etc/ssh/ssh_host_*_key"):
        maxm = max_by_path.get(path, 0o600)  # private host keys: root only
        extra = mode & 0o777 & ~maxm
        if owner != "root":
            res.add("high", f"{path}: owner '{owner}' instead of root")
        if extra:
            wr_others = bool(mode & 0o002)
            rd_others = bool(mode & 0o004) and (path in SECRET_PATHS or "ssh_host" in path)
            sev = "critical" if (wr_others or rd_others) else "high"
            why = ("writable by everyone" if wr_others else
                   "contains secrets and is readable by everyone" if rd_others else "")
            res.add(sev, f"{path}: permissions too wide ({oct(mode & 0o777)[2:]}, expected at most {oct(maxm)[2:]})", why)
            flagged_dirs.add(path)

    # ---- /tmp and similar: must have the sticky bit (users can delete only their own files)
    for mode, owner, group, path in _stat(rem, " ".join(STICKY_DIRS)):
        if not mode & 0o1000:
            res.add("high", f"{path}: missing sticky bit", "Any user could delete other users' files.")

    # ---- home directories, ~/.ssh and private keys
    for u in users:
        if u["bad"] or not valid_path(u["home"]) or (u["shell"] in NOLOGIN and u["uid"] != 0):
            continue
        h, n = u["home"], u["name"]
        names = [h, f"{h}/.ssh", f"{h}/.ssh/authorized_keys"] + [f"{h}/.ssh/{k}" for k in
                 ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")]
        # Compare by UID, not by name: two accounts sharing a UID are the same identity for the kernel,
        # and "stat %U" shows only the FIRST name for that UID. Comparing names would report another
        # user's home as owned by the wrong account (the real issue, the shared UID, is already reported
        # by the accounts check).
        for mode, owner, group, path in _stat(rem, " ".join(shlex.quote(x) for x in names), numeric=True):
            base = os.path.basename(path)
            if owner not in (str(u["uid"]), "0"):
                res.add("high", f"{path}: belongs to UID {owner} instead of '{n}' (UID {u['uid']})")
            if path == h and mode & 0o002:
                res.add("high", f"Home directory of '{n}' writable by everyone", path)
                flagged_dirs.add(path)   # not repeated among the "writable directories in home" (low)
            elif path == h and mode & 0o020:
                res.add("medium", f"Home directory of '{n}' writable by the group", path)
            elif base == ".ssh" and mode & 0o022:
                res.add("high", f"{path}: writable by group/others (SSH rejects it or it can be tampered with)")
            elif base == "authorized_keys" and mode & 0o022:
                res.add("high", f"{path}: writable by group/others: anyone can add keys")
            elif base.startswith("id_") and mode & 0o077:
                res.add("critical" if mode & 0o004 else "high",
                        f"SSH private key readable by others: {path}", f"mode={oct(mode)[2:]}")

    # ---- world-writable directories WITHOUT sticky bit (dangerous)
    ww = rem.run(f"for m in {MOUNTS}; do nice -n 19 ionice -c3 find \"$m\" -xdev {PRUNE} -type d -perm -0002 "
                 "! -perm -1000 -print 2>/dev/null; done | head -60", sudo=True, timeout=ctx.opts.scan_timeout).out
    locks, home_items = [], []
    for d in ww.splitlines():
        if d in flagged_dirs:
            continue  # already reported (with the correct severity) by the system permissions check
        if LOCK_RE.search(d):
            locks.append(d)
        elif d.startswith("/home/"):
            home_items.append(d)
        else:
            res.add("high" if d.startswith(SENSITIVE_PREFIXES) else "medium",
                    "World-writable directory without sticky bit", d)

    # ---- world-writable files in system directories
    wf = rem.run(f"nice -n 19 ionice -c3 find -H /etc /usr /bin /sbin /lib /lib64 /opt -xdev {PRUNE} -type f "
                 "-perm -0002 -print 2>/dev/null | head -60", sudo=True, timeout=ctx.opts.scan_timeout).out
    for f in wf.splitlines():
        if SECRET_FILE_RE.search(os.path.basename(f)):
            res.add("high", "Credentials file writable by everyone", f)
        else:
            res.add("high", "System file writable by everyone", f)
    # Data and websites: less severe than a system file, but anyone on the server can alter them.
    wd = rem.run(f"nice -n 19 ionice -c3 find -H /srv /var/www /var/backups /home -xdev {PRUNE} -type f "
                 "-perm -0002 -print 2>/dev/null | head -60", sudo=True, timeout=ctx.opts.scan_timeout).out
    for f in wd.splitlines():
        if SECRET_FILE_RE.search(os.path.basename(f)):
            # Configuration files with passwords/keys (wp-config.php, .env, *.key...): whoever modifies them
            # can make the service execute code or steal the credentials.
            res.add("high", "Credentials file writable by everyone", f)
        elif LOCK_RE.search(f):
            locks.append(f)
        elif f.startswith("/home/"):
            home_items.append(f)
        else:
            res.add("medium", "Data file writable by everyone", f)
    if home_items:
        res.add("low", f"{len(home_items)} files/directories open to everyone in home directories",
                "Risk limited to other local users. Examples: " + ", ".join(home_items[:10]))
    if locks:
        res.add("info", f"{len(locks)} lock files/directories writable by everyone (normal for locks)",
                ", ".join(locks[:6]))

    # ---- SUID/SGID inventory: comparison with the list of expected names
    suid = rem.run(f"for m in {MOUNTS}; do nice -n 19 ionice -c3 find \"$m\" -xdev {PRUNE} -type f "
                   "\\( -perm -4000 -o -perm -2000 \\) -printf '%m|%u|%p\\n' 2>/dev/null; done | head -400",
                   sudo=True, timeout=ctx.opts.scan_timeout).out
    unknown_pkg, unpackaged = [], []
    count = 0
    for line in suid.splitlines():
        mode, _, rest = line.partition("|")
        owner, _, path = rest.partition("|")
        if not re.fullmatch(r"[0-7]{3,4}", mode) or not path.startswith("/"):
            continue
        count += 1
        base = os.path.basename(path)
        if path.startswith(BAD_PREFIXES) and base == "chrome-sandbox":
            # Electron apps (VS Code, Discord, desktop apps...) require chrome-sandbox to be SUID root for
            # their sandbox. Common and intended, but still a root program outside the packages, in a user
            # directory, never touched by system updates.
            res.add("high", "chrome-sandbox of an Electron app, SUID root, in a user directory",
                    f"{path} (mode {mode}). Verify that the app is trustworthy and up to date.")
        elif path.startswith(BAD_PREFIXES):
            res.add("critical", "SUID/SGID file in a directory where it should not be", f"{path} (mode {mode}, owner {owner})")
        elif owner != "root":
            res.add("high", "SUID/SGID file not owned by root", f"{path} (owner {owner})")
        elif base not in KNOWN_SUID:
            if valid_path(path) and not owned(ctx, path):
                if _is_shell_copy(ctx, path):
                    res.add("critical", "SUID/SGID file that is a shell or an interpreter: direct shortcut to root",
                            f"{path} (mode {mode}, owner {owner})")
                else:
                    unpackaged.append(path)
            else:
                unknown_pkg.append(path)
        elif not path.startswith(STD_PREFIXES):
            res.add("medium", "Known SUID/SGID file in an unusual location", path)
    res.data["suid_sgid_total"] = count
    _check_caps(ctx, res)
    if unpackaged:
        # One line per group: typical of software installed with its own installer (e.g. VMware).
        res.add("high", f"{len(unpackaged)} SUID/SGID files outside packages and not among the known ones",
                "Verify which software they come from and that it is up to date: " + ", ".join(unpackaged[:15]))
    if unknown_pkg:
        res.add("low", f"SUID/SGID from packages not in the known list ({len(unknown_pkg)})",
                ", ".join(unknown_pkg[:25]))
    return res
