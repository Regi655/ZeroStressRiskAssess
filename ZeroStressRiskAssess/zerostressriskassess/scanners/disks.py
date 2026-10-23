"""Health and integrity of disks and filesystems (READ-ONLY checks only).

WARNING: `fsck` is NEVER run on a mounted filesystem (it can damage it). Only these are read: the SMART status
(the disk's own diagnosis), software RAID, I/O errors in the kernel log and the filesystem flags.

WHY it belongs in a risk assessment: availability and integrity are security properties too. A failing disk
means data loss; a filesystem the kernel remounted read-only after an error means services that cannot write
(logs included).

smartmontools is installed for the check and removed at the end, like ClamAV (toolmgr.py). Not in a container:
there the disks belong to the host. On a virtual machine the disks are virtual: no SMART, and that is normal.
"""
from __future__ import annotations

import re

from ..models import ScanResult
from ..validate import valid_path

DEV_RE = re.compile(r"/dev/[A-Za-z0-9/_-]+")
TYPE_RE = re.compile(r"[a-z0-9,+]+")
ATA_BAD = {"Reallocated_Sector_Ct": ("medium", "reallocated sectors"),
           "Current_Pending_Sector": ("high", "sectors pending reallocation"),
           "Offline_Uncorrectable": ("high", "uncorrectable sectors"),
           "Reported_Uncorrect": ("high", "uncorrectable errors reported"),
           "UDMA_CRC_Error_Count": ("low", "CRC errors (often the cable)")}
KERNEL_ERR = (r"I/O error|Buffer I/O error|EXT4-fs error|XFS .*(corruption|error)|BTRFS.*(error|corrupt)|"
              r"ata[0-9.]+: .*(error|failed|exception)|blk_update_request")


def parse_smart(res: ScanResult, dev: str, out: str, rc: int) -> None:
    """Interpret the output of `smartctl -H -A` (ATA/SATA, SCSI, NVMe)."""
    m = re.search(r"SMART overall-health self-assessment test result:\s*(\w+)", out)
    s = re.search(r"SMART Health Status:\s*(.+)", out)
    verdict = m.group(1) if m else (s.group(1).strip() if s else None)
    if verdict is not None and verdict.upper() not in ("PASSED", "OK"):
        res.add("critical", f"Disk {dev}: SMART reports problems ({verdict})", "The disk declares itself failing.")
    elif verdict is not None:
        res.add("info", f"Disk {dev}: SMART OK")
    # The exit code is a bit mask: 8 = disk failing, 16 = prefail attribute below threshold,
    # 64/128 = errors in the error log / in the self-test log (smartctl(8), EXIT STATUS).
    if rc & 8:
        res.add("critical", f"Disk {dev}: SMART, disk failing (exit code {rc})")
    if rc & 16:
        res.add("high", f"Disk {dev}: SMART, pre-failure attribute below threshold")
    if rc & (64 | 128):
        res.add("medium", f"Disk {dev}: SMART, errors recorded in the disk logs")
    for line in out.splitlines():
        t = line.split()
        if len(t) >= 10 and t[1] in ATA_BAD and t[9].isdigit() and int(t[9]) > 0:
            sev, why = ATA_BAD[t[1]]
            res.add(sev, f"Disk {dev}: {why}: {t[9]}")
    pu = re.search(r"Percentage Used:\s+(\d+)%", out)
    if pu and int(pu.group(1)) >= 80:
        res.add("high" if int(pu.group(1)) >= 100 else "medium", f"Disk {dev}: NVMe worn out at {pu.group(1)}%")
    cw = re.search(r"Critical Warning:\s+(0x[0-9a-fA-F]+)", out)
    if cw and int(cw.group(1), 16) != 0:
        res.add("high", f"Disk {dev}: NVMe Critical Warning {cw.group(1)}")
    me = re.search(r"Media and Data Integrity Errors:\s+(\d+)", out)
    if me and int(me.group(1)) > 0:
        res.add("high", f"Disk {dev}: NVMe media and data integrity errors: {me.group(1)}")


def run(ctx) -> ScanResult:
    res, rem = ScanResult("disks"), ctx.rem
    container = bool(ctx.cache.get("container"))

    # ---- SMART (smartmontools, installed by the tool if missing)
    if container:
        res.add("info", "Target in a container: physical disk health (SMART) belongs to the host, not checked")
    elif "smartmontools" in ctx.tools_ok:
        devs = []
        for line in rem.run("smartctl --scan", sudo=True).out.splitlines():
            parts = line.split("#")[0].split()
            if not parts or not DEV_RE.fullmatch(parts[0]):
                continue
            dtype = parts[parts.index("-d") + 1] if "-d" in parts and parts.index("-d") + 1 < len(parts) else "auto"
            if TYPE_RE.fullmatch(dtype):
                devs.append((parts[0], dtype))
        for dev, dtype in devs:
            r = rem.run(f"smartctl -H -A -d {dtype} {dev}", sudo=True, timeout=120)
            parse_smart(res, dev, r.out, r.rc)
        res.data["smart_devices"] = [d for d, _ in devs]
        if not devs:
            res.add("info", "No disk with SMART found (normal on virtual machines)")
    else:
        res.add("info", "smartmontools not available: physical disk health not verified")

    # ---- software RAID: "[UU_]" = one member missing
    for line in rem.run("cat /proc/mdstat 2>/dev/null").out.splitlines():
        m = re.search(r"\[\d+/\d+\]\s+\[([U_]+)\]", line)
        if m and "_" in m.group(1):
            res.add("critical", "Degraded RAID (one or more disks missing)", line.strip())

    # ---- I/O and filesystem errors in the kernel log
    # Floppy (fd0, always present in VMware VMs), loop devices and optical drives are excluded: they give harmless
    # read errors when no medium is inserted. In a container dmesg is the host's (and usually not readable).
    if not container:
        errs = rem.run(f"dmesg 2>/dev/null | grep -iE '{KERNEL_ERR}' "
                       r"| grep -ivE '\bfd[0-9]\b|floppy|\bloop[0-9]+\b|\bsr[0-9]+\b' | tail -20",
                       sudo=True).out.strip()
        if errs:
            n = len(errs.splitlines())
            res.add("high", f"I/O or filesystem errors in the kernel log ({n} recent lines)",
                    "\n".join(errs.splitlines()[-4:]))

    # ---- mounted filesystems: UNEXPECTED read-only = the kernel remounted them after an error.
    # Read-only alone proves nothing: images, recovery partitions and appliances are mounted ro on purpose (the
    # development sandbox has three ext4 filesystems mounted ro, norecovery). It counts only if the kernel log
    # says it remounted it, or if /etc/fstab mounts it read-write.
    remounts = "" if container else rem.run(
        "dmesg 2>/dev/null | grep -iE 'remount.*read-only|read-only.*remount' | tail -20", sudo=True).out
    fstab = {}
    for line in rem.run("findmnt --fstab -rno TARGET,OPTIONS 2>/dev/null").out.splitlines():
        t = line.split()
        if len(t) == 2:
            fstab[t[0]] = t[1].split(",")
    intended_ro = []
    for line in rem.run("findmnt -rno SOURCE,FSTYPE,TARGET,OPTIONS").out.splitlines():
        p = line.split()
        if len(p) < 4 or not p[0].startswith("/dev/") or p[0].startswith("/dev/loop"):
            continue
        src, fstype, target, opts = p[0], p[1], p[2], p[3].split(",")
        if fstype in ("ext2", "ext3", "ext4", "xfs", "btrfs") and "ro" in opts:
            dev = src.split("[")[0].rsplit("/", 1)[-1]
            hit = [x for x in remounts.splitlines() if dev and re.search(rf"\b{re.escape(dev)}\b", x)]
            if hit:
                res.add("high", f"Filesystem {target} remounted read-only by the kernel after an error",
                        f"{src} ({fstype}): {hit[-1].strip()[:200]}")
            elif target in fstab and "ro" not in fstab[target]:
                res.add("medium", f"Filesystem {target} is read-only, but /etc/fstab mounts it read-write",
                        f"{src} ({fstype}): the kernel may have blocked it after an error (read dmesg)")
            else:
                intended_ro.append(target)
        if fstype.startswith("ext") and DEV_RE.fullmatch(src):
            st = rem.run(f"tune2fs -l {src} 2>/dev/null | grep -i 'Filesystem state'", sudo=True).out
            low = st.lower()
            # "Filesystem state: clean" is the normal value; "not clean" or "... with errors" are not.
            if st and ("not clean" in low or "error" in low or "clean" not in low):
                res.add("medium", f"Filesystem {target} reports errors or is not clean", st.strip())
        if fstype == "btrfs" and valid_path(target) and rem.run("command -v btrfs").rc == 0:
            for stat in rem.run(f"btrfs device stats {target}", sudo=True).out.splitlines():
                if re.search(r"\s[1-9]\d*$", stat):
                    res.add("high", f"btrfs {target}: device errors", stat.strip())

    if intended_ro:
        res.add("info", f"Read-only filesystems, as configured: {', '.join(intended_ro[:10])}")

    # ---- inodes: a disk can be "full" with free space left
    for line in rem.run("df -Pi -x tmpfs -x devtmpfs -x squashfs -x overlay").out.splitlines()[1:]:
        t = line.split()
        if len(t) >= 6 and t[4].rstrip("%").isdigit() and int(t[4].rstrip("%")) >= 90:
            res.add("high", f"Inodes almost exhausted on {t[5]}: {t[4]}")
    return res
