"""Baseline hardening without Lynis: kernel parameters, mount options, login.defs, auditing, time
synchronisation, network interfaces in promiscuous mode.

Lynis performs hundreds of checks, but it must be copied to the target, takes about ninety seconds
and its suggestions are generic ("one or more sysctl values differ from the scan profile"). This module
covers the most important checks, each reporting the value found, the expected value and the
rationale. When Lynis is active its equivalent suggestions (KRNL-6000, AUTH-9328, ACCT-9628) are not
repeated.

Severities are calibrated so that a fresh installation does not receive "medium" findings: medium is
reserved for missing real defences (ASLR disabled, link protection in /tmp disabled, weak password
hashes); everything else is "low" and grouped in a single line.

The ACTIVE value (/proc/sys) is read rather than the configuration files: a file may say 1 while the
kernel says 0 if /usr/lib/sysctl.d was never applied. The kernel value is what counts.
"""
from __future__ import annotations

import re

from ..models import ScanResult

SYSCTL = {
    # key: (accepted values, severity if different, rationale)
    "kernel.randomize_va_space": ({"2"}, "medium", "ASLR: with 0 or 1 memory addresses are predictable and "
                                  "exploits become much easier"),
    "fs.protected_symlinks": ({"1"}, "medium", "without it, a user can make a root program follow a link in "
                              "/tmp and write a system file"),
    "fs.protected_hardlinks": ({"1"}, "medium", "without it, a user can create hard links to other users' files (e.g. SUID)"),
    "net.ipv4.conf.all.accept_source_route": ({"0"}, "medium", "the sender chooses the packet route: "
                                              "bypasses filters and controls"),
    "fs.protected_fifos": ({"1", "2"}, "low", "FIFOs in shared directories such as /tmp"),
    "fs.protected_regular": ({"1", "2"}, "low", "regular files in shared directories such as /tmp"),
    "fs.suid_dumpable": ({"0", "2"}, "low", "with 1, SUID programs write readable core dumps (secrets in memory)"),
    "kernel.kptr_restrict": ({"1", "2"}, "low", "kernel addresses help exploit writers"),
    "kernel.dmesg_restrict": ({"1"}, "low", "kernel messages can reveal addresses and details"),
    "kernel.yama.ptrace_scope": ({"1", "2", "3"}, "low", "with 0, a process can read the memory of others "
                                 "owned by the same user (e.g. browser passwords)"),
    "kernel.unprivileged_bpf_disabled": ({"1", "2"}, "low", "unprivileged BPF has been the basis of several "
                                         "privilege escalations"),
    "net.ipv4.conf.all.accept_redirects": ({"0"}, "low", "a router on the network can redirect traffic"),
    "net.ipv4.conf.all.send_redirects": ({"0"}, "low", "needed by routers only"),
    "net.ipv4.tcp_syncookies": ({"1"}, "low", "SYN flood protection"),
    "net.ipv4.conf.all.rp_filter": ({"1", "2"}, "low", "drops packets with a spoofed source"),
    "net.ipv4.ip_forward": ({"0"}, "low", "the machine forwards packets like a router"),
}
# Packet forwarding is required by Docker, libvirt, LXD, Kubernetes...: ip_forward=1 is intended there.
FORWARD_OK = re.compile(r"\b(docker0|br-[0-9a-f]+|virbr\d+|lxdbr\d+|cni\d*|flannel|cali|tun\d+|wg\d+)\b")
MOUNT_OPTS = {"/tmp": ("nodev", "nosuid", "noexec"), "/dev/shm": ("nodev", "nosuid", "noexec"),
              "/var/tmp": ("nodev", "nosuid", "noexec")}

SCRIPT = r"""
c=0; { [ -f /.dockerenv ] || [ -f /run/.containerenv ]; } && c=1; echo "CONTAINER|$c"
for k in %s; do p=/proc/sys/$(echo "$k" | tr . /); [ -r "$p" ] && echo "SYS|$k|$(cat "$p")"; done
for m in /tmp /dev/shm /var/tmp; do o=$(findmnt -rno OPTIONS --target "$m" 2>/dev/null | head -1); \
  t=$(findmnt -rno TARGET --target "$m" 2>/dev/null | head -1); echo "MNT|$m|$t|$o"; done
grep -E '^[[:space:]]*(ENCRYPT_METHOD|UMASK)[[:space:]]' /etc/login.defs 2>/dev/null | sed 's/^/LOGIN|/'
for s in auditd chronyd chrony systemd-timesyncd ntpd ntp; do pgrep -x "$s" >/dev/null 2>&1 && echo "PROC|$s"; done
ip -o link show 2>/dev/null | sed 's/^/LINK|/'
""" % " ".join(SYSCTL)


def parse(text: str) -> dict:
    d = {"sys": {}, "mnt": {}, "login": {}, "proc": set(), "links": [], "container": False}
    for line in text.splitlines():
        tag, _, rest = line.partition("|")
        if tag == "SYS":
            k, _, v = rest.partition("|")
            d["sys"][k] = v.strip()
        elif tag == "MNT":
            m, t, o = (rest.split("|") + ["", ""])[:3]
            d["mnt"][m] = (t, set(o.split(",")) if o else set())
        elif tag == "LOGIN":
            p = rest.split()
            if len(p) >= 2:
                d["login"][p[0]] = p[1]
        elif tag == "PROC":
            d["proc"].add(rest.strip())
        elif tag == "LINK":
            d["links"].append(rest)
        elif tag == "CONTAINER":
            d["container"] = rest.strip() == "1"
    return d


def evaluate(d: dict) -> list:
    """[(severity, title, detail)]. Pure function."""
    out, lows = [], []
    links = " ".join(d["links"])
    if d["container"]:
        out.append(("info", "Target is a container: kernel parameters, auditing and clock belong to the host",
                    "The values read are the host's: they must be checked there."))
    else:
        for k, (ok, sev, why) in SYSCTL.items():
            v = d["sys"].get(k)
            if v is None or v in ok:
                continue
            if k == "net.ipv4.ip_forward" and FORWARD_OK.search(links):
                continue
            if sev == "medium":
                out.append(("medium", f"Kernel: {k} = {v} (expected {'/'.join(sorted(ok))})", why + "."))
            else:
                lows.append(f"{k}={v} (expected {'/'.join(sorted(ok))}: {why})")
        if "auditd" not in d["proc"]:
            out.append(("low", "No system auditing (auditd not running)",
                        "Without auditing, after an incident it is impossible to reconstruct who did what (access to "
                        "sensitive files, sudo usage, account changes)."))
        if not d["proc"] & {"chronyd", "chrony", "systemd-timesyncd", "ntpd", "ntp"}:
            out.append(("low", "No clock synchronisation service running (chrony, timesyncd, ntpd)",
                        "With a wrong time, logs from different machines cannot be correlated and certificates may "
                        "appear expired or not yet valid."))
    if lows:
        out.append(("low", f"Kernel parameters to harden ({len(lows)})", "; ".join(lows)))

    for m, need in MOUNT_OPTS.items():
        target, opts = d["mnt"].get(m, ("", set()))
        if target != m:
            continue   # not a separate mount: the "separate partition" advice comes from Lynis
        missing = [o for o in need if o not in opts]
        if missing:
            out.append(("low", f"{m} mounted without {', '.join(missing)}",
                        "Anyone can write there: with noexec/nosuid/nodev a file left there cannot be executed "
                        "or used as a device."))

    enc = d["login"].get("ENCRYPT_METHOD", "").upper()
    if enc in ("MD5", "DES", "NONE"):
        out.append(("medium", f"New passwords stored with a weak hash (ENCRYPT_METHOD {enc} in /etc/login.defs)",
                    "Use SHA512 or YESCRYPT: a stolen MD5/DES hash is cracked quickly."))
    um = d["login"].get("UMASK", "")
    if re.fullmatch(r"0?[0-7]{3}", um) and not int(um, 8) & 0o002:
        out.append(("medium", f"UMASK {um} in /etc/login.defs: new files are writable by everyone",
                    "Default value 022 (or 027 for more confidentiality)."))

    promisc = [ln.split(":")[1].strip() for ln in d["links"]
               if "PROMISC" in ln.split(">")[0] and " master " not in ln and ":" in ln]
    if promisc:
        out.append(("medium", f"Network interface in promiscuous mode: {', '.join(promisc)}",
                    "It receives all network traffic, not only its own: this is what a sniffer does. Normal only "
                    "with intended analysis tools (tcpdump, IDS) or virtual bridges."))
    return out


def run(ctx) -> ScanResult:
    res = ScanResult("hardening")
    d = parse(ctx.rem.run(SCRIPT, sudo=True).out)
    res.data.update({"sysctl": d["sys"], "container": d["container"]})
    for sev, title, detail in evaluate(d):
        res.add(sev, title, detail)
    if not res.findings:
        res.add("info", "Baseline hardening: no problems in the checks performed")
    return res
