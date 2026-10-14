"""Portable Lynis: copied to the target, executed from a temporary root-owned directory, then deleted.

Advantages over the distribution package:
  - nothing is installed: no package, no dependencies, nothing to uninstall afterwards;
  - the version is chosen by the operator (distribution repositories often ship releases that are
    years old and miss checks);
  - Lynis logs and reports stay in the temporary directory and are removed with it; with the package
    they would remain in /var/log, in clear text, listing the system's weaknesses.
Validated with Lynis 3.1.8 from the official repository: 89 seconds, exit code 0, logs and report
only in the temporary directory. Lynis still runs `apt-get update` and `apt-get check`, as the
packaged version does.

Copy integrity (Lynis runs as root, so nobody else must be able to modify it):
  1. the archive is uploaded to the SSH user's home directory with mode 600;
  2. root verifies its SHA-256 against the value computed locally and refuses to extract on mismatch;
  3. it is extracted into a directory created by mktemp (unpredictable name, mode 700, root-owned).
"""
from __future__ import annotations

import hashlib
import io
import re
import shlex
import tarfile
from pathlib import Path

REMOTE_DIR_RE = re.compile(r"^/tmp/zerostressriskassess-lynis\.[A-Za-z0-9]{6}$")
ARCHIVE = ".riskassess_lynis.tgz"


def check_dir(path: str) -> str:
    """Lynis version in the local directory, or ValueError with the reason."""
    p = Path(path).expanduser()
    if not (p / "lynis").is_file() or not (p / "include").is_dir():
        raise ValueError(f"{path}: not a Lynis directory (the 'lynis' file and the 'include' directory are required). "
                         "Download it with: git clone https://github.com/CISOfy/lynis")
    m = re.search(r'PROGRAM_VERSION="([0-9.]+)"', (p / "lynis").read_text(errors="replace"))
    return m.group(1) if m else "?"


def available(path: str) -> bool:
    try:
        check_dir(path)
        return True
    except ValueError:
        return False


def pack(path: str):
    """(in-memory tar.gz archive, sha256). .git is excluded: 2.8 MB instead of tens."""
    p = Path(path).expanduser()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(str(p), arcname="lynis", filter=lambda ti: None if "/.git" in ti.name or ti.name.endswith("/.git")
                else ti)
    data = buf.getvalue()
    return data, hashlib.sha256(data).hexdigest()


def run_lynis(rem, path: str, timeout: int):
    """Copy, run and DELETE Lynis on the target. Returns (exit code, screen output, report.dat)."""
    data, sha = pack(path)
    tmp = f"{rem.home()}/{ARCHIVE}"
    rem.upload_bytes(tmp, data)
    q = shlex.quote(tmp)
    prep = rem.run(
        f"set -e; [ \"$(sha256sum < {q} | cut -d' ' -f1)\" = {sha} ] || {{ rm -f {q}; echo CHECKSUM; exit 3; }}; "
        f"D=$(mktemp -d /tmp/zerostressriskassess-lynis.XXXXXX); chmod 700 \"$D\"; "
        f"tar -xzf {q} -C \"$D\" --no-same-owner; rm -f {q}; chown -R root:root \"$D\"; echo \"$D\"",
        sudo=True)
    d = prep.out.strip().splitlines()[-1] if prep.out.strip() else ""
    if prep.rc != 0 or not REMOTE_DIR_RE.match(d):
        rem.run(f"rm -f {q}", sudo=True)
        return prep.rc or 1, "Portable Lynis preparation failed: " + prep.out[-300:], ""
    try:
        r = rem.run(f"cd {d}/lynis && ./lynis audit system --cronjob --logfile {d}/lynis.log "
                    f"--report-file {d}/report.dat", sudo=True, timeout=timeout)
        rep = rem.run(f"cat {d}/report.dat", sudo=True).out
        return r.rc, r.out, rep
    finally:
        rem.run(f"rm -rf {d}", sudo=True)


CLEANUP = "rm -rf /tmp/zerostressriskassess-lynis.?????? 2>/dev/null; true"
