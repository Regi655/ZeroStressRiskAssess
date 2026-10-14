"""Validation of UNTRUSTED input (command-line arguments and text returned by the target).

An allow-list is used (accept only values with exactly the expected shape) instead of a deny-list
(strip dangerous characters), which inevitably misses cases. fullmatch is used instead of match with
^...$ because `$` also accepts a trailing newline that an attacker could exploit.
"""
from __future__ import annotations

import ipaddress
import re

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOST_RE = re.compile(rf"{_LABEL}(?:\.{_LABEL})*")
_PKG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._-]{0,127}")
_PID_RE = re.compile(r"[0-9]{1,9}")
_PORTS_RE = re.compile(r"[0-9TU:,\-]{0,200}")
_PATH_RE = re.compile(r"/[A-Za-z0-9._/@+,:=-]{0,255}")


def valid_host(h: str) -> bool:
    """IPv4/IPv6 address or hostname. Must not start with '-' (it would be parsed as an option)."""
    if not h or len(h) > 253:
        return False
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return bool(_HOST_RE.fullmatch(h))


def valid_ports(p: str) -> bool:
    return bool(_PORTS_RE.fullmatch(p))


def is_pid(s: str) -> bool:
    # str.isdigit() also accepts Unicode digits such as '²', hence the regex.
    return bool(_PID_RE.fullmatch(s))


def only_pids(items) -> list:
    return [i for i in items if is_pid(i)]


def split_pkgs(names):
    """Split into (plausible package names, anomalous names)."""
    ok, bad = set(), []
    for n in names:
        (ok.add(n) if _PKG_RE.fullmatch(n) else bad.append(n))
    return sorted(ok), bad


def valid_path(p: str) -> bool:
    return bool(_PATH_RE.fullmatch(p)) and ".." not in p.split("/")


def safe_name(s: str) -> str:
    """Make a value safe for use in a file or directory name."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)
