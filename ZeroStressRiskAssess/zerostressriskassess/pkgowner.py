"""Lookup of the package owning a file, taking usrmerge into account.

On Ubuntu 22.04 and later (and recent Debian/RHEL) /bin, /sbin and /lib are symlinks to /usr/bin,
/usr/sbin and /usr/lib, but the package database still records the OLD path: `dpkg -S /usr/bin/ls`
finds nothing while `dpkg -S /bin/ls` returns "coreutils". Both forms of the path are therefore tried.
"""
from __future__ import annotations

import re
import shlex

_PKG_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._-]{0,127}")
_MERGED = ("/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/lib64/")


def path_variants(path: str) -> list:
    """['/usr/bin/ls'] -> ['/usr/bin/ls', '/bin/ls']"""
    out = [path]
    if path.startswith(_MERGED):
        out.append(path[len("/usr"):])
    return out


def owned(ctx, path: str) -> bool:
    """True if at least one form of the path belongs to a package (the exit code is used rather than
    the text, so it works with any locale).
    """
    tool = "dpkg -S" if ctx.osinfo.pkg_mgr == "apt" else "rpm -qf"
    for v in path_variants(path):
        if ctx.rem.run(f"{tool} {shlex.quote(v)}").rc == 0:
            return True
    return False


def package_of(ctx, path: str):
    """Name of the package owning the file, or None."""
    tool = "dpkg -S" if ctx.osinfo.pkg_mgr == "apt" else "rpm -qf --qf '%{NAME}\\n'"
    for v in path_variants(path):
        r = ctx.rem.run(f"{tool} {shlex.quote(v)} 2>/dev/null")
        if r.rc == 0 and r.out.strip():
            first = r.out.splitlines()[0]
            # dpkg: "coreutils: /usr/bin/ls" or "libc6:amd64: /lib/..."; rpm: "coreutils"
            name = first.split(":")[0].strip() if ctx.osinfo.pkg_mgr == "apt" else first.strip()
            return name if _PKG_NAME.fullmatch(name) else None
    return None


def verify_file(ctx, path: str):
    """(package, intact) for a file.

    intact = True  -> the file matches the checksum recorded by the official package;
             False -> the file DIFFERS from the packaged one (modified);
             None  -> the file belongs to no package and cannot be verified this way.
    Equivalent to `dpkg -V PACKAGE` restricted to a single file.
    """
    pkg = package_of(ctx, path)
    if not pkg:
        return None, None
    tool = "dpkg -V " if ctx.osinfo.pkg_mgr == "apt" else "rpm -V "
    out = ctx.rem.run(tool + shlex.quote(pkg), sudo=True, timeout=300).out
    names = set(path_variants(path))
    for line in out.splitlines():
        tok = line.split()
        # format: "??5??????   /usr/bin/ls" (5 in third position = checksum mismatch)
        if len(tok) >= 2 and tok[-1] in names and len(tok[0]) > 2 and tok[0][2] == "5":
            return pkg, False
    return pkg, True
