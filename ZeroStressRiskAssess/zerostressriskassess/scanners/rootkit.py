"""Rootkit search with chkrootkit and rkhunter.

The two tools use different techniques (signatures of known rootkits, suspicious files and permissions, hash
comparison against a baseline): running both reduces blind spots. Both produce many FALSE POSITIVES, so every
warning is cross-checked against the package database before it is rated (pkgowner.verify_file): a command
reported as "INFECTED" that is identical to the official package is a known false positive, not a rootkit.

- chkrootkit is installed temporarily with apt (with binutils if missing: it needs `strings`) and removed at
  the end, like ClamAV.
- rkhunter is NEVER installed by the tool: its file check compares the current state with a baseline created
  earlier, and a baseline created now, on a system that may already be compromised, would certify tampered
  files as good. If the target already has it, it is used as it is (`--propupd` is never run).
"""
from __future__ import annotations

import re

from ..models import ScanResult, mark_timeout
from ..pkgowner import verify_file

# Services that legitimately open raw sockets (DHCP, network management): reported by the ifpromisc test.
KNOWN_SNIFFER_RE = re.compile(r"systemd-networkd|dhclient|dhcpcd|NetworkManager|wpa_supplicant|dhcpd|udhcpc|"
                              r"iwd$|connmand", re.I)

CHECKING_RE = re.compile(r"^Checking `([A-Za-z0-9._+-]+)'\.\.\. INFECTED")
FROM_PKG_RE = re.compile(r"\s*\[From (?:Debian|RPM) package: ([^\]]+)\]$")
# e.g. "Possible Linux BPFDoor Malware installed:" or, with the name of the sub-check, "chkdirs: Possible LKM Trojan installed:"
ALERT_HDR_RE = re.compile(r"^(?:[\w-]+: )?Possible .+ installed:?$", re.I)
PROC_STACK_RE = re.compile(r"^/proc/(\d{1,9})/")

MISSING_RE = re.compile(r"can't find [`'\"]?([\w.+-]+)")
# Error messages of the commands chkrootkit runs (ip, netstat...), not results: in the development sandbox
# "RTNETLINK answers: Invalid argument" appeared 33 times and used to become 33 medium findings.
TOOL_ERROR_RE = re.compile(r"^(RTNETLINK answers:|Cannot open|.*: No such file or directory$|"
                           r".*: Permission denied$|.*: Operation not permitted$)", re.I)


def parse_chkrootkit(text: str) -> dict:
    """Output of `chkrootkit -q` (0.55 and 0.58 formats) -> structure. Pure function.

    0.58 adds "WARNING: " before the headers and "[From Debian package: X]" after the hidden files that belong
    to a package: both are handled instead of being treated as anomalies.
    """
    d = {"infected_cmds": [], "alerts": [], "hidden_pkg": [], "hidden_other": [], "sniffers": [], "other": [],
         "missing": [], "errors": []}
    section = None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        mm = MISSING_RE.search(line)
        if mm:
            # "chkrootkit: can't find `strings'.": chkrootkit stops immediately. It is not an anomaly of the
            # target but a check that was not performed (seen on a minimal Docker container).
            d["missing"].append(mm.group(1))
            continue
        if TOOL_ERROR_RE.match(line):
            # "/proc/1/fd/0: Permission denied" x 19 in the sandbox: it used to end up among the "hidden files".
            norm = re.sub(r"\d+", "N", line)
            if norm not in d["errors"]:
                d["errors"].append(norm)
            continue
        if line.upper().startswith("WARNING: "):
            line = line[9:].strip()
        low = line.lower()
        m = CHECKING_RE.match(line)
        if m:
            d["infected_cmds"].append(m.group(1))
            section = None
        elif low.startswith("the following suspicious files"):
            section = "hidden"
        elif low.startswith("output from ifpromisc"):
            section = "promisc"
        elif "INFECTED" in line.upper() or ALERT_HDR_RE.match(line):
            d["alerts"].append({"title": line, "files": []})
            section = "alert"
        elif line.startswith("/") and section == "alert":
            d["alerts"][-1]["files"].append(line)
        elif section == "alert" and d["alerts"][-1]["title"].lower().startswith("chkdirs:"):
            # chkdirs prints its own output (directory names or notices) under the alert: it belongs to it.
            d["alerts"][-1]["files"].append(line)
        elif line.startswith("/"):
            pm = FROM_PKG_RE.search(line)
            (d["hidden_pkg"] if pm else d["hidden_other"]).append(FROM_PKG_RE.sub("", line))
        elif section == "promisc":
            if "PACKET SNIFFER(" in line.upper():
                d["sniffers"].append(line)
        else:
            section = None
            d["other"].append(line)
    return d


def _verify_cmds(ctx, names):
    """For each command reported INFECTED: path, package, intact? (see pkgowner.verify_file)."""
    names = [n for n in names if re.fullmatch(r"[A-Za-z0-9._+-]{1,64}", n)]
    if not names:
        return {}
    # `type -P` rather than `command -v`: for shell BUILT-INS (echo, test...) `command -v` only answers "echo",
    # while chkrootkit is interested in the FILE /usr/bin/echo (seen on the laptop).
    out = ctx.rem.run("for c in " + " ".join(names) + '; do echo "$c|$(type -P $c 2>/dev/null)"; done').out
    res = {}
    for line in out.splitlines():
        name, _, path = line.partition("|")
        if name in names:
            res[name] = (path, *verify_file(ctx, path)) if path.startswith("/") else (path, None, None)
    return res


def _verify_pids(ctx, pids):
    out = ctx.rem.run("for p in " + " ".join(pids) + '; do echo "$p|$(readlink /proc/$p/exe 2>/dev/null)"; done',
                      sudo=True).out
    res = {}
    for line in out.splitlines():
        pid, _, exe = line.partition("|")
        if pid in pids and exe.startswith("/") and not exe.endswith("(deleted)"):
            res[pid] = (exe, *verify_file(ctx, exe))
    return res


def run_chkrootkit(ctx) -> ScanResult:
    res = ScanResult("chkrootkit")
    if "chkrootkit" not in ctx.tools_ok:
        return res.skip("chkrootkit not available on the target")
    # -q = quiet: prints only what is not "not infected" / "nothing found".
    r = ctx.rem.run("chkrootkit -q", sudo=True, timeout=ctx.opts.scan_timeout)
    res.raw = r.out
    mark_timeout(res, r)
    d = parse_chkrootkit(r.out)
    if d["missing"]:
        # Info and "error" status: it is a check that did not run, not a weakness of the target. A medium finding
        # would add a fake risk to the table; the "error" status keeps it visible among the checks performed.
        res.status = "error"
        res.add("info", "chkrootkit NOT run: programs missing on the target ({})".format(", ".join(d["missing"])),
                "The chkrootkit checks (tampered commands, hidden files, sniffers) were not performed: the result "
                "does NOT mean 'no rootkit'.")

    # "Checking `basename'... INFECTED": chkrootkit looks for strings typical of rootkits inside the binary, and
    # with recent versions of the programs it sometimes finds them by chance. Before reporting a rootkit, the
    # file is compared with the official package (like running `dpkg -V coreutils` by hand).
    for name, (path, pkg, ok) in sorted(_verify_cmds(ctx, d["infected_cmds"]).items()):
        if ok:
            res.add("low", f"chkrootkit: '{name}' reported INFECTED, but identical to package {pkg}",
                    f"{path}: checksum equal to the official one. Known chkrootkit false positive with recent "
                    "versions of the programs.")
        elif ok is False:
            res.add("critical", f"chkrootkit: '{name}' INFECTED and DIFFERENT from package {pkg}",
                    f"{path}: the checksum does not match the official one. Possibly replaced binary.")
        else:
            res.add("critical", f"chkrootkit: '{name}' INFECTED, cannot be verified (outside packages)", path or "?")
    for a in d["alerts"]:
        title, files = a["title"], a["files"]
        if title.lower().startswith("chkdirs:"):
            # chkdirs looks for hidden directories by comparing each directory's link count with the number of
            # its subdirectories. That only works on file systems that keep the classic link count: on BTRFS
            # and on overlayfs (Docker containers) the counts never match and chkdirs itself prints "It seems
            # you are using BTRFS...". In that case the warning carries no information (verified in the lab).
            if any("btrfs" in f.lower() for f in files):
                res.add("info", "chkrootkit: hidden-directory check (chkdirs) not reliable on this file system",
                        "chkdirs compares directory link counts, which do not add up on BTRFS and overlayfs "
                        "(containers): its 'Possible LKM Trojan' warning is meaningless here. chkrootkit's own "
                        "notice: " + "; ".join(files[:3]))
            else:
                res.add("high", f"chkrootkit: {title.rstrip(':')}",
                        "Directories whose link count does not match their content (possible kernel rootkit hiding "
                        "directories): " + (", ".join(files[:10]) or "no detail printed"))
            continue
        pids = [m.group(1) for f in files for m in [PROC_STACK_RE.match(f)] if m]
        if pids:
            # E.g. BPFDoor: chkrootkit points at processes (/proc/PID/stack) waiting for network packets in a
            # certain way. If the process's program belongs to an intact package it is a false positive (it
            # happens with legitimate network services such as chronyd).
            procs = _verify_pids(ctx, pids)
            clean = [f"PID {p}: {e} ({pkg}, intact)" for p, (e, pkg, ok) in procs.items() if ok]
            dirty = [p for p in pids if not (p in procs and procs[p][2])]
            if not dirty:
                res.add("low", f"chkrootkit: {title.rstrip(':')} - processes from intact packages "
                        "(probable false positive)", "; ".join(clean))
            else:
                res.add("high", f"chkrootkit: {title.rstrip(':')}",
                        "processes to verify: " + ", ".join(f"PID {p}" for p in dirty)
                        + ("; intact: " + "; ".join(clean) if clean else ""))
            continue
        if "XOR.DDOS" in title.upper():
            # From the chkrootkit 0.58b source: the "signature" is ANY executable file under /tmp, plus
            # /etc/cron.hourly/udev.sh and gcc.sh. Only those two are a specific indicator; an executable in /tmp
            # may be an installer or a test program (in the sandbox: chromedriver, busybox, Python libraries).
            ioc = [f for f in files if re.search(r"/etc/cron\.hourly/(udev|gcc)\.sh$", f)]
            tmp = [f for f in files if f not in ioc]
            if ioc:
                res.add("critical", "chkrootkit: files typical of the Linux.Xor.DDoS malware", ", ".join(ioc))
            if tmp:
                res.add("medium", f"Executable files in /tmp ({len(tmp)})",
                        "chkrootkit heuristic for Xor.DDoS: it reports every executable under /tmp, where malware "
                        "often downloads itself; installers and test programs end up there too. Verify: "
                        + ", ".join(tmp[:10]))
            continue
        res.add("critical", "chkrootkit reports INFECTED", title + (" | files: " + ", ".join(files[:10]) if files else ""))

    for line in d["sniffers"]:
        # NetworkManager, wpa_supplicant, systemd-networkd and dhclient open "sniffing" sockets to work (DHCP,
        # Wi-Fi): known ifpromisc false positive. The others remain to be verified.
        procs = re.findall(r"(/[^\s\[,()]+)\[\d+\]", line)
        if procs and all(KNOWN_SNIFFER_RE.search(p) for p in procs):
            res.add("info", "chkrootkit: 'sniffer' network sockets of known network services (normally fine)", line)
        else:
            res.add("high", "chkrootkit: network interface in promiscuous mode / sniffer", line)

    for line in dict.fromkeys(d["other"]):   # a repeated line = one finding
        res.add("medium", "chkrootkit: item to verify", line)
    if d["errors"]:
        res.add("info", f"chkrootkit: error messages from the commands it runs ({len(d['errors'])} distinct)",
                "They are not results: some checks may be incomplete. " + "; ".join(d["errors"][:5]))
    if d["hidden_other"]:
        # A single finding for the whole list: one line per file would raise the risk through noise.
        res.add("low", f"chkrootkit: {len(d['hidden_other'])} hidden files/directories to verify",
                "Often false positives. Examples: " + ", ".join(d["hidden_other"][:12]))
    if d["hidden_pkg"]:
        res.add("info", f"chkrootkit: {len(d['hidden_pkg'])} hidden files owned by packages (normal)",
                ", ".join(d["hidden_pkg"][:5]))
    res.data["hidden_files_listed"] = len(d["hidden_other"]) + len(d["hidden_pkg"])
    res.data["hidden_files_unpackaged"] = len(d["hidden_other"])
    return res


def run_rkhunter(ctx) -> ScanResult:
    res, rem = ScanResult("rkhunter"), ctx.rem
    if "rkhunter" not in ctx.tools_ok:
        res.status = "skipped"
        # Info, not "low": it is advice, not a weakness of the target, and it must not weigh on the risk.
        res.add("info", "rkhunter is not installed on the target: no rkhunter check",
                "Install it while the system is in a known clean state, create the baseline then "
                "(rkhunter --propupd) and schedule periodic checks.")
        return res

    # Its baseline is only as trustworthy as the moment it was created: the date goes into the report so the
    # reader can judge.
    b = rem.run("stat -c '%y' /var/lib/rkhunter/db/rkhunter.dat", sudo=True)
    if b.rc != 0 or not b.out:
        res.add("medium", "rkhunter without a baseline (file properties database missing)",
                "The file properties check is meaningless without a baseline.")
    else:
        res.data["baseline"] = b.out[:19]
        res.add("info", f"rkhunter baseline of {b.out[:19]}", "Trustworthy only if created when the system was clean.")
    pk = rem.run("grep -hE '^[[:space:]]*PKGMGR' /etc/rkhunter.conf /etc/rkhunter.conf.local "
                 "/etc/rkhunter.d/*.conf 2>/dev/null | tail -1", sudo=True).out.strip()
    if not pk or pk.split("=")[-1].strip().upper() in ("", "NONE"):
        res.add("low", "rkhunter does not use the package manager as reference (PKGMGR)",
                "Recommended PKGMGR=DPKG: files are compared with the distribution checksums, independently of the "
                "local baseline.")

    # Update the signature databases; if it fails (no network) the existing ones are used.
    up = rem.run("rkhunter --update --nocolors", sudo=True, timeout=600)
    # `rkhunter --propupd` is NEVER run (see the module docstring).
    # --sk = do not wait for key presses; --rwo = report warnings only.
    r = rem.run("rkhunter --check --sk --nocolors --rwo", sudo=True, timeout=ctx.opts.scan_timeout)
    res.raw = r.out
    mark_timeout(res, r)
    if up.rc not in (0, 2):  # 2 = no update available, fine
        res.add("info", "rkhunter signature update failed: using the ones already present")
    for sev, title, detail in classify_rkhunter(ctx, parse_rkhunter(r.out)):
        res.add(sev, title, detail)
    return res


def parse_rkhunter(text: str) -> list:
    """Groups the output into warnings: a "Warning: ..." line plus the indented lines that follow it.
    Previously every line became a finding (30 lines for 10 warnings). Pure function."""
    blocks = []
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith((" ", "\t")) and blocks:
            blocks[-1].append(line.strip())
        else:
            blocks.append([line.strip()])
    return blocks


def classify_rkhunter(ctx, blocks) -> list:
    out = []
    # Users and groups created by the packages the tool installed (e.g. 'clamav'): rkhunter sees them as "new".
    by_tool = {p.split("-")[0] for p in ctx.cache.get("tool_installed", ())}
    for b in blocks:
        head, rest = b[0], b[1:]
        low = head.lower()
        detail = " | ".join(b)
        if "rootkit" in low and ("found" in low or "infected" in low) and "not found" not in low:
            out.append(("critical", "rkhunter: rootkit detected", detail))
            continue
        if "file properties have changed" in low:
            path = next((x.split(":", 1)[1].strip() for x in rest if x.startswith("File:")), "")
            pkg, ok = verify_file(ctx, path) if path.startswith("/") else (None, None)
            if ok:
                out.append(("low", f"rkhunter: {path} changed since the baseline, but identical to package {pkg}",
                            "Legitimate package update: refresh the baseline with `rkhunter --propupd` "
                            "(only if you are sure the system is clean)."))
            elif ok is False:
                out.append(("high", f"rkhunter: {path} differs from both the baseline and package {pkg}",
                            "The file does not match the official version: possible replacement. " + detail))
            else:
                out.append(("medium", f"rkhunter: {path or 'file'} changed since the baseline (outside packages)", detail))
            continue
        m = re.match(r"Warning: (User|Group) '([^']+)' has been added", head)
        if m and m.group(2).lower() in by_tool:
            out.append(("info", f"rkhunter: {m.group(1).lower()} '{m.group(2)}' added by the tool itself",
                        "Created by temporarily installing the scanning tools (removed with them)."))
            continue
        out.append(("medium", "rkhunter: " + head.replace("Warning: ", "", 1)[:200], " | ".join(rest)))
    return out
