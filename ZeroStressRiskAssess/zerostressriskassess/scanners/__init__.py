"""Check registry.

Adding a check = writing `run(ctx) -> ScanResult` and adding one line below.
EXTERNAL checks run on the controller (nmap, ssh-audit) before logging into the target.
INTERNAL checks run on the target (over SSH, or directly with --local): fast read-only checks first,
heavy ones last (Lynis ~90 s, ClamAV several minutes).
"""
from . import (accounts, clamav_scan, containers, cve_scan, disks, dns, firewall, ftp, hardening, integrity,
               listeners, lynis_scan, mysql, nmap_scan, permissions, persistence, platform, resources, rootkit,
               services, ssh_audit, sshd_conf, sudoers, updates)

EXTERNAL = [("nmap", nmap_scan.run), ("ssh_audit", ssh_audit.run)]

INTERNAL = [
    ("resources", resources.run),   # first: CPU is measured before the other checks load the machine
    ("accounts", accounts.run),
    ("sudoers", sudoers.run),
    ("sshd", sshd_conf.run),
    ("permissions", permissions.run),
    ("persistence", persistence.run),
    ("integrity", integrity.run),
    ("services", services.run),
    ("listeners", listeners.run),
    ("firewall", firewall.run),
    ("hardening", hardening.run),
    ("containers", containers.run),
    ("dns", dns.run),
    ("mysql", mysql.run),
    ("ftp", ftp.run),
    ("updates", updates.run),
    ("cve", cve_scan.run),
    ("platform", platform.run),
    ("disks", disks.run),
    ("lynis", lynis_scan.run),
    ("chkrootkit", rootkit.run_chkrootkit),
    ("rkhunter", rootkit.run_rkhunter),
    ("clamav", clamav_scan.run),
]

ALL_NAMES = [n for n, _ in EXTERNAL + INTERNAL]
