"""Antivirus scan with ClamAV.

ClamAV is resource-intensive (about 1 GB of signatures in RAM, many files read), therefore:
 * by default only the directories where malware usually hides are scanned (temporary directories,
   home directories, /etc, binaries); --clamav-full scans everything;
 * it runs with the lowest CPU and I/O priority (nice/ionice) so as not to disrupt the server;
 * if free memory is too low the scan is skipped rather than risking the OOM killer.
"""
from __future__ import annotations

import re

import shlex

from ..models import ScanResult, mark_timeout

DEFAULT_DIRS = ("/tmp /var/tmp /dev/shm /home /root /etc /usr/local /opt /var/www /srv "
                "/usr/bin /usr/sbin /bin /sbin")
# --clamav-quick: only the usual malware locations on servers, without /home (slow on a workstation).
QUICK_DIRS = "/tmp /var/tmp /dev/shm /root /etc /usr/local /opt /var/www /srv"
# Directories made almost entirely of regenerable caches: very many files, low risk. On a real
# laptop scanning /home including them took more than an hour. Listed in the report for transparency.
EXCLUDE_DIRS = [r"/\.cache/", r"/node_modules/", r"/\.git/objects/", r"/\.local/share/Steam/",
                r"/\.local/share/Trash/", r"/\.cargo/registry/", r"/\.npm/_cacache/", r"/snap/[^/]+/[^/]+/\.cache/"]
MIN_FREE_MB = 1500
FOUND_RE = re.compile(r"^(.+): (.+) FOUND$")


def run(ctx) -> ScanResult:
    res, rem = ScanResult("clamav"), ctx.rem
    if "clamav" not in ctx.tools_ok:
        return res.skip("ClamAV not available on the target")

    free = rem.run("awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo").out
    if free.isdigit() and int(free) < MIN_FREE_MB:
        return res.skip(f"Insufficient available RAM ({free} MB < {MIN_FREE_MB} MB): ClamAV scan skipped")

    # Without up-to-date signatures ClamAV detects nothing (or does not start at all).
    fc = rem.run("freshclam --quiet", sudo=True, timeout=900)
    res.data["freshclam_rc"] = fc.rc
    if fc.rc != 0:
        # This limits the ANALYSIS (the target cannot reach database.clamav.net) and is not a weakness of
        # the target: info. If no signatures exist at all, clamscan cannot start and the check fails.
        res.add("info", "ClamAV signatures not updated: the target cannot reach database.clamav.net", fc.out[-300:])

    excl = " ".join("--exclude-dir=" + shlex.quote(x) for x in EXCLUDE_DIRS)
    if ctx.opts.clamav_full:
        excl += " " + " ".join(f"--exclude-dir=^/{d}" for d in ("proc", "sys", "dev", "run"))
        target, mode = "/", "full"
    else:
        dirs, mode = (QUICK_DIRS, "quick") if getattr(ctx.opts, "clamav_quick", False) else (DEFAULT_DIRS, "standard")
        # Only existing directories are passed, otherwise clamscan fails.
        target = '$(for d in %s; do [ -d "$d" ] && printf "%%s " "$d"; done)' % dirs
    res.data.update({"mode": mode, "excluded": EXCLUDE_DIRS})

    # `timeout` runs ON THE TARGET, so the target itself stops clamscan when the limit is reached.
    # Without it our own limit only closed the connection and clamscan kept running, even after the
    # tool had finished and ClamAV had been uninstalled.
    limit = max(60, ctx.opts.scan_timeout - 60)
    cmd = (f"timeout -k 30 {limit} nice -n 19 ionice -c3 clamscan -r -i --max-filesize=100M "
           f"--max-scansize=300M {excl} {target}")
    r = rem.run(cmd, sudo=True, timeout=ctx.opts.scan_timeout)
    res.raw = r.out
    if mark_timeout(res, r):
        res.add("info", "Hint: --clamav-quick (without /home) or a longer --scan-timeout",
                f"Current limit {limit // 60} minutes, {mode} mode.")
    # rc: 0 = clean, 1 = infections found, 2 = error, 124 = interrupted by timeout
    if r.rc == 2:
        res.status = "error"
        if "No supported database files" in r.out:
            res.add("info", "ClamAV NOT run: no antivirus signatures available on the target",
                    "The antivirus check was not performed (the report does not state 'no malware'). The target "
                    "must reach database.clamav.net, or an internal mirror configured in freshclam.conf.")
        else:
            res.add("info", "clamscan terminated with an error", r.out[-500:])
        return res

    for line in r.out.splitlines():
        m = FOUND_RE.match(line.strip())
        if m:
            if "EICAR" in m.group(2).upper():
                # The standard antivirus test file is harmless by definition and must not outrank real issues.
                res.add("low", "EICAR antivirus test file (harmless)",
                        f"{m.group(1)}: the standard file used to verify that an antivirus works, not malware. "
                        "If nobody placed it there on purpose, someone is testing the antivirus or file uploads.")
            else:
                res.add("high", f"ClamAV: {m.group(2)}", m.group(1))
        elif line.startswith(("Scanned files:", "Infected files:", "Time:")):
            k, _, v = line.partition(":")
            res.data[k.strip().lower().replace(" ", "_")] = v.strip()
    # State what was NOT scanned: "0 infections" with /home excluded does not mean "/home is clean".
    if mode == "quick":
        res.add("info", "ClamAV in quick mode: /home NOT scanned",
                f"Scanned only: {QUICK_DIRS}. To include home directories use the "
                "standard mode (default) or --clamav-full.")
    elif mode == "standard":
        res.add("info", "ClamAV in standard mode: only high-risk directories scanned",
                f"{DEFAULT_DIRS}. For the whole disk: --clamav-full.")
    return res
