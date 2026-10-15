"""Target operating system detection (first step of every assessment).

Package names, package manager and repositories differ between distributions. This module
confirms that the target is Ubuntu/Debian (apt) and whether it is a container, in which case
some checks concern the host rather than the target.
"""
from __future__ import annotations

from dataclasses import dataclass


class UnsupportedOS(Exception):
    pass


@dataclass
class OSInfo:
    id: str
    version_id: str
    pretty: str
    pkg_mgr: str   # always "apt": only Ubuntu/Debian targets are accepted
    kernel: str
    arch: str
    container: bool = False


def detect(rem) -> OSInfo:
    # /etc/os-release is the systemd standard for identifying the distribution.
    r = rem.run("cat /etc/os-release")
    kv = {}
    for line in r.out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k] = v.strip().strip('"')

    # ID_LIKE names the parent distribution (Ubuntu -> "debian"). The project is designed and tested for
    # Ubuntu and works on Debian derivatives; RHEL/Rocky support from the original project is listed
    # under future work in the README.
    ids = {kv.get("ID", "").lower(), *kv.get("ID_LIKE", "").lower().split()}
    if not ids & {"debian", "ubuntu"}:
        raise UnsupportedOS(f"Unsupported distribution: {kv.get('PRETTY_NAME', '?')} "
                            "(supported: Ubuntu and Debian derivatives)")
    mgr = "apt"
    cont = rem.run("[ -f /.dockerenv ] || [ -f /run/.containerenv ] || "
                   "grep -qaE 'container=(docker|podman|lxc)' /proc/1/environ 2>/dev/null", sudo=True).rc == 0

    return OSInfo(
        id=kv.get("ID", "?"),
        version_id=kv.get("VERSION_ID", "?"),
        pretty=kv.get("PRETTY_NAME", "?"),
        pkg_mgr=mgr,
        kernel=rem.run("uname -r").out,
        arch=rem.run("uname -m").out,
        container=cont,
    )
