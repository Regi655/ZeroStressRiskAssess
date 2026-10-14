"""Disk encryption and Secure Boot.

These protect against someone with physical access to the MACHINE, not against network attackers.
  - unencrypted disk: whoever steals a laptop (or a decommissioned disk) can read everything,
    passwords included, simply by attaching the disk to another computer;
  - Secure Boot disabled: the firmware boots anything, including a tampered bootloader or kernel.
The weight depends on the machine type: very high on a laptop, low on a server in a locked room,
negligible on a VM (encryption and boot are the hypervisor's responsibility) and none in a container
(disk and firmware belong to the host).

Encryption is detected by walking from the root device to its parents with `lsblk -s`: if one of them
is of type crypt (LUKS / dm-crypt) the data on disk is encrypted. Secure Boot is read from the EFI
SecureBoot variable (last byte: 1 = enabled), without external programs.
"""
from __future__ import annotations

import re

from ..models import ScanResult

SCRIPT = r"""
c=0; { [ -f /.dockerenv ] || [ -f /run/.containerenv ]; } && c=1; echo "CONTAINER|$c"
echo "HV|$(grep -c -m1 -w hypervisor /proc/cpuinfo 2>/dev/null)"
echo "VIRT|$(systemd-detect-virt 2>/dev/null)"
echo "VENDOR|$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)"
echo "CHASSIS|$(cat /sys/class/dmi/id/chassis_type 2>/dev/null)"
echo "BAT|$(ls -d /sys/class/power_supply/BAT* 2>/dev/null | wc -l)"
src=$(findmnt -no SOURCE / 2>/dev/null | sed 's/\[.*//'); echo "ROOT|$src"
# Caution: with an EMPTY argument lsblk -s lists ALL disks. Only if it is a block device.
[ -n "$src" ] && [ -b "$src" ] && lsblk -s -P -o NAME,TYPE,FSTYPE "$src" 2>/dev/null | sed 's/^/CHAIN|/'
tail -n +2 /proc/swaps 2>/dev/null | while read -r d t rest; do
  echo "SWAP|$d|$t"
  [ -b "$d" ] && lsblk -s -P -o NAME,TYPE,FSTYPE "$d" 2>/dev/null | sed "s#^#SWAPCHAIN|$d|#"
done
if [ -d /sys/firmware/efi ]; then
  echo "EFI|yes"
  f=$(ls /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | head -1)
  [ -n "$f" ] && echo "SB|$(od -An -t u1 "$f" 2>/dev/null | tr -s ' ')"
else
  echo "EFI|no"
fi
command -v mokutil >/dev/null 2>&1 && echo "MOK|$(mokutil --sb-state 2>&1 | head -1)"
echo "LOCK|$(cat /sys/kernel/security/lockdown 2>/dev/null)"
"""
LAPTOP_CHASSIS = {"8", "9", "10", "14", "30", "31", "32"}   # SMBIOS: laptop, notebook, tablet, convertible...
VM_VENDORS = re.compile(r"qemu|vmware|virtualbox|innotek|xen|kvm|microsoft corporation|parallels|bochs", re.I)
PAIR_RE = re.compile(r'(\w+)="([^"]*)"')


def parse(text: str) -> dict:
    """SCRIPT output -> data. Pure function."""
    d = {"chain": [], "swaps": {}, "sb": None, "mok": "", "efi": None}
    for line in text.splitlines():
        tag, _, rest = line.partition("|")
        if tag == "CHAIN":
            d["chain"].append(dict(PAIR_RE.findall(rest)))
        elif tag == "SWAP":
            dev, _, typ = rest.partition("|")
            d["swaps"][dev] = {"type": typ.strip(), "chain": []}
        elif tag == "SWAPCHAIN":
            dev, _, pairs = rest.partition("|")
            d["swaps"].setdefault(dev, {"type": "?", "chain": []})["chain"].append(dict(PAIR_RE.findall(pairs)))
        elif tag == "SB":
            nums = rest.split()
            d["sb"] = nums[-1] == "1" if nums else None
        elif tag == "EFI":
            d["efi"] = rest.strip() == "yes"
        elif tag in ("CONTAINER", "HV", "VIRT", "VENDOR", "CHASSIS", "BAT", "ROOT", "MOK", "LOCK"):
            d[tag.lower()] = rest.strip()
    if d["sb"] is None and d["mok"]:
        d["sb"] = "enabled" in d["mok"].lower() if "secureboot" in d["mok"].lower() else None
    return d


def encrypted(chain: list) -> bool:
    return any(n.get("TYPE") == "crypt" or n.get("FSTYPE") == "crypto_LUKS" for n in chain)


CONTAINER_VIRT = {"docker", "podman", "lxc", "lxc-libvirt", "systemd-nspawn", "openvz", "rkt", "wsl", "proot", "pouch"}


def kind(d: dict) -> str:
    if d.get("container") == "1" or d.get("virt") in CONTAINER_VIRT:
        return "container"
    if d.get("hv", "0") not in ("", "0") or d.get("virt", "") not in ("", "none") or VM_VENDORS.search(d.get("vendor", "")):
        return "vm"
    if d.get("bat", "0") not in ("", "0") or d.get("chassis") in LAPTOP_CHASSIS:
        return "laptop"
    return "physical"


def evaluate(d: dict) -> list:
    """[(severity, title, detail)]. Pure function."""
    k, out = kind(d), []
    label = {"vm": "virtual machine", "laptop": "laptop", "physical": "physical machine"}.get(k, k)
    if k == "container":
        return [("info", "Target is a container: disk encryption and Secure Boot concern the host", "")]
    out.append(("info", f"Machine type: {label}", "From battery/chassis (SMBIOS), the CPU 'hypervisor' flag, systemd-detect-virt."))

    root_enc = encrypted(d["chain"])
    if not d["chain"]:
        out.append(("info", "Root filesystem encryption cannot be verified", f"Root device: {d.get('root') or '?'}"))
    elif root_enc:
        out.append(("info", "System root on an encrypted disk (LUKS/dm-crypt)",
                    " <- ".join(f"{n.get('NAME')}({n.get('TYPE')})" for n in d["chain"])))
    else:
        sev = {"laptop": "high", "physical": "low", "vm": "info"}[k]
        out.append((sev, "System disk NOT encrypted",
                    {"laptop": "On a laptop this is the main risk in case of theft or loss: whoever has the disk "
                               "reads everything, passwords and keys included. LUKS must be chosen at installation.",
                     "physical": "Risk for stolen or decommissioned disks: assess according to where the machine is located.",
                     "vm": "On a VM, virtual disk encryption is the responsibility of the hypervisor or the storage."}[k]))
    for dev, s in d["swaps"].items():
        if dev.startswith("/dev/zram") or s["type"] == "file":
            continue   # zram lives in RAM; a swap file sits on a filesystem (encrypted if the root is)
        if root_enc and not encrypted(s["chain"]):
            out.append(("medium" if k == "laptop" else "low", f"Swap NOT encrypted with an encrypted root: {dev}",
                        "Memory written to swap (including passwords and keys) ends up on disk in clear text."))

    if d.get("efi") is False:
        out.append(("info" if k == "vm" else "low", "Boot in BIOS (legacy) mode: Secure Boot not available", ""))
    elif d.get("sb") is True:
        out.append(("info", "Secure Boot enabled", d.get("mok", "")))
    elif d.get("sb") is False:
        out.append(({"laptop": "medium", "physical": "low", "vm": "info"}[k], "Secure Boot DISABLED",
                    "The firmware also boots tampered bootloaders or kernels: an attacker with physical access (or root) "
                    "can install something that starts before the operating system."))
    else:
        out.append(("info", "Secure Boot state cannot be read", ""))
    if d.get("lock"):
        out.append(("info", f"Kernel lockdown: {d['lock']}", "The active mode is shown in square brackets."))
    return out


def run(ctx) -> ScanResult:
    res = ScanResult("platform")
    d = parse(ctx.rem.run(SCRIPT, sudo=True).out)
    res.data = {"kind": kind(d), "root_encrypted": encrypted(d["chain"]), "efi": d.get("efi"), "secure_boot": d.get("sb")}
    for sev, title, detail in evaluate(d):
        res.add(sev, title, detail)
    return res
