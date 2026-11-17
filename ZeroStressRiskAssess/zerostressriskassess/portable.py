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
import shutil
import subprocess
import tarfile
from pathlib import Path

# Lynis runs AS ROOT on every target, so the copy sent is the one validated, not "whatever is on master today".
# Upstream has no 3.1.8 tag: this is the master commit validated in the lab (PROGRAM_VERSION 3.1.8). To update:
# read the changes upstream, run the lab, then change this line (setup.sh reads it from here).
LYNIS_REPO = "https://github.com/CISOfy/lynis"
LYNIS_COMMIT = "9319416fa0726369ab0a48f686155a90363f3f9c"
DEFAULT_DIR = Path(__file__).resolve().parent.parent / "vendor" / "lynis"

REMOTE_DIR_RE = re.compile(r"^/tmp/zerostressriskassess-lynis\.[A-Za-z0-9]{6}$")
ARCHIVE = ".riskassess_lynis.tgz"


def check_dir(path: str) -> str:
    """Lynis version in the local directory, or ValueError with the reason.

    A git checkout (vendor/lynis from setup.sh) must be exactly LYNIS_COMMIT with no local change. The default
    directory must be such a checkout. A different directory given with --lynis-dir and without .git is the
    operator's own choice: accepted, and the report says it was not verified ("unverified" in the version)."""
    p = Path(path).expanduser()
    if not (p / "lynis").is_file() or not (p / "include").is_dir():
        raise ValueError(f"{path}: not a Lynis directory (the 'lynis' file and the 'include' directory are required). "
                         "Run ./setup.sh")
    m = re.search(r'PROGRAM_VERSION="([0-9.]+)"', (p / "lynis").read_text(errors="replace"))
    version = m.group(1) if m else "?"
    if (p / ".git").exists():
        _verify_checkout(p)
        return version
    if p.resolve() == DEFAULT_DIR:
        raise ValueError(f"{path}: not a git checkout, so it cannot be verified. Remove it and run ./setup.sh")
    return version + " (unverified: --lynis-dir without git)"


def _verify_checkout(p: Path) -> None:
    git = shutil.which("git")
    if not git:
        raise ValueError(f"{p}: git is needed to verify the Lynis copy (sudo apt install git)")
    head = subprocess.run([git, "-C", str(p), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    if head != LYNIS_COMMIT:
        raise ValueError(f"{p} is at commit {head[:12] or '?'}, not the validated {LYNIS_COMMIT[:12]}: "
                         "run ./setup.sh (Lynis runs as root on the target, only the validated copy is sent)")
    dirty = subprocess.run([git, "-C", str(p), "status", "--porcelain", "--untracked-files=all"],
                           capture_output=True, text=True).stdout.strip()
    if dirty:
        raise ValueError(f"{p}: files changed or added after the download ({dirty.splitlines()[0]} ...): "
                         "not sent. Run: git -C vendor/lynis checkout -- . && git -C vendor/lynis clean -fd")


def available(path: str) -> bool:
    return why_unavailable(path) is None


def why_unavailable(path: str):
    """None if the directory can be sent, otherwise the reason (shown in the report)."""
    try:
        check_dir(path)
        return None
    except ValueError as exc:
        return str(exc)


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
