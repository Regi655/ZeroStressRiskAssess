"""External reconnaissance only (--recon-only): what can be learned about a machine WITHOUT logging into it.

Used when logging in is not allowed or not wanted: a machine that may already be compromised and must not be
contaminated before a forensic analysis, a system outside the agreed scope for internal checks, or an
unsupported distribution. Nothing is installed, copied, executed or written on the target: the only traces are
the network connections, which the target's own logs may record (sshd, web server, firewall), as for any scan.

The checks run from the controller:
  - nmap with the "safe" NSE scripts and ssh-audit (the same EXTERNAL checks as a normal assessment);
  - dns_recon: recursion, version.bind and, for the zones given with --dns-zone, zone transfer (AXFR);
  - mysql_recon: the MySQL/MariaDB greeting (version, TLS offered or not, controller allowed or not).
They produce the same finding titles as the full checks, so the risk rules and the correlation apply unchanged.
guess_os() reads the distribution from the service banners: a hint, never a verified fact.
"""
from __future__ import annotations

import re

from .. import mysqlprobe
from ..models import ScanResult
from .dns import _external, _Pending
from .mysql import clean_version

# Distribution markers in service banners ("OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", "Apache httpd 2.4.58 ((Ubuntu))",
# "OpenSSH 8.7 (protocol 2.0)" with ".el9" packages...). The first match wins.
OS_MARKERS = [
    (re.compile(r"ubuntu", re.I), "Ubuntu", "debian"),
    (re.compile(r"debian|\+deb\d+", re.I), "Debian", "debian"),
    (re.compile(r"\bel(\d+)\b|red ?hat|rocky|alma|centos", re.I), "RHEL family (RHEL, Rocky, Alma, CentOS)", "rhel"),
    (re.compile(r"\bfc\d+\b|fedora", re.I), "Fedora", "rhel"),
    (re.compile(r"suse", re.I), "SUSE", "suse"),
    (re.compile(r"alpine", re.I), "Alpine", "alpine"),
    (re.compile(r"freebsd", re.I), "FreeBSD", "bsd"),
    (re.compile(r"windows|microsoft", re.I), "Windows", "windows"),
]


def guess_os(banners: list) -> dict:
    """{"label", "family", "evidence"} from service banners. Pure function."""
    for rx, label, family in OS_MARKERS:
        for b in banners:
            if rx.search(b):
                return {"label": label, "family": family, "evidence": b[:120]}
    return {"label": "", "family": "", "evidence": ""}


def _nmap_ports(ctx):
    """Ports nmap saw open, or None if nmap did not run (skipped or failed)."""
    return ctx.cache.get("nmap_open") if "nmap_open" in ctx.cache else None


def dns_recon(ctx) -> ScanResult:
    res = ScanResult("dns")
    ports = _nmap_ports(ctx)
    zones = list(getattr(ctx.opts, "dns_zones", []) or [])
    out = _Pending(res)
    # restricted_acl/version_hidden are configuration facts: unknown from outside, so the probes speak alone.
    _external(out, ctx.rem.host, zones, restricted_acl=False, version_hidden=False)
    probe = res.data.get("probe", {})
    answered = probe.get("recursion", {}).get("answered") or probe.get("version") is not None
    tcp53 = ports is not None and any(p.get("port") == 53 for p in ports)
    if not answered and not tcp53 and not res.findings:
        return res.skip("No DNS server answered on port 53 (UDP) and nmap did not see 53/tcp open")
    if not zones:
        res.add("info", "DNS: zone transfer (AXFR) not tested",
                "From outside the tool cannot know which zones the server hosts: pass them with --dns-zone ZONE.")
    return res


def mysql_recon(ctx) -> ScanResult:
    res = ScanResult("mysql")
    ports = _nmap_ports(ctx)
    if ports is None:
        cand = [3306]   # nmap did not run: the standard port is probed directly
    else:
        cand = [p["port"] for p in ports if p.get("port") == 3306 or "mysql" in str(p.get("service", "")).lower()]
    if not cand:
        return res.skip("No MySQL/MariaDB port seen open by nmap")
    port = cand[0]
    res.data["port"] = port
    g = mysqlprobe.probe(ctx.rem.host, port)
    res.data["greeting"] = {k: v for k, v in g.items() if k in ("reachable", "kind", "version", "ssl", "code")}
    # The version is in the greeting; when the controller is refused, the error message names the server instead
    # ("Host ... is not allowed to connect to this MariaDB server").
    flavor = "MariaDB" if "mariadb" in (str(g.get("version", "")) + str(g.get("message", ""))).lower() else "MySQL"
    if g.get("kind") == "greeting":
        res.add("medium", f"{flavor} reachable from the controller (port {port})",
                f"The server answers with version {clean_version(g['version'])}. A database should be reachable only "
                "from the application servers: firewall or bind-address on an internal address.")
        if g.get("ssl") is False:
            res.add("medium", f"{flavor} listening on the network without TLS",
                    "The server greeting does not offer TLS (CLIENT_SSL bit absent): passwords and data travel in clear.")
    elif g.get("kind") == "error":
        res.add("low", f"{flavor}: port {port} reachable, but the controller address is not authorised",
                g.get("message", "")[:200])
    else:
        return res.skip(f"Port {port} not answering as MySQL/MariaDB from the controller")
    return res


RECON = [("dns", dns_recon), ("mysql", mysql_recon)]
