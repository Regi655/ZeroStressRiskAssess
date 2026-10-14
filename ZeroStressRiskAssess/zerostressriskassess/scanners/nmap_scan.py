"""EXTERNAL scan: nmap runs on the controller, not on the target.

This is the view of an attacker on the network. What answers from outside can differ considerably
from what listens inside the machine (firewall, NAT). The scan runs BEFORE anything is installed on
the target, so it captures the real exposure rather than one altered by our own tools.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

from .. import nse
from ..models import SEVERITIES, ScanResult
from ..validate import valid_host, valid_ports

SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}  # 0 = most severe

# port -> (severity, reason). Not a verdict: an alert to be verified.
RISKY = {
    21: ("medium", "FTP: clear-text credentials"),
    23: ("high", "Telnet: everything in clear text, obsolete protocol"),
    69: ("medium", "TFTP: no authentication"),
    111: ("low", "rpcbind exposed"),
    135: ("medium", "RPC/MSRPC exposed"),
    139: ("medium", "NetBIOS exposed"),
    445: ("high", "SMB exposed: frequent target of exploits/ransomware"),
    512: ("high", "rexec: obsolete r* service"),
    513: ("high", "rlogin: obsolete r* service"),
    514: ("high", "rsh: obsolete r* service"),
    1433: ("medium", "SQL Server database exposed"),
    2375: ("critical", "Docker API without TLS: remote control of the system"),
    3306: ("medium", "MySQL/MariaDB database exposed"),
    3389: ("medium", "RDP exposed"),
    5432: ("medium", "PostgreSQL database exposed"),
    5900: ("medium", "VNC exposed"),
    6379: ("high", "Redis exposed (often without a password)"),
    9200: ("medium", "Elasticsearch exposed"),
    11211: ("medium", "Memcached exposed"),
    27017: ("high", "MongoDB exposed"),
    # Ports typical of backdoors and attack tools: no reason to exist on a normal server.
    1337: ("medium", "'elite' port, often used by attack tools and backdoors"),
    4444: ("high", "default Metasploit / reverse shell port"),
    5555: ("medium", "Android Debug Bridge or backdoor"),
    12345: ("high", "historic backdoor port (NetBus)"),
    31337: ("high", "historic backdoor port (Back Orifice, 'elite')"),
}

# Software behind the port (from the banner detected by nmap) that should not be exposed.
BANNER_RISKS = [
    (re.compile(r"SimpleHTTP|http\.server|BaseHTTP", re.I), "high",
     "Python development web server: publishes a directory without authentication (typical for data exfiltration)"),
    (re.compile(r"Werkzeug|Flask dev|php.*development server", re.I), "medium",
     "development web server: not meant to be exposed"),
]


def script_list(opts) -> list:
    if not getattr(opts, "nse", True):
        return []
    return list(nse.SAFE_SCRIPTS) + (list(nse.TLS_SCRIPTS) if getattr(opts, "nse_tls", False) else [])


def parse_xml(root, now=None):
    """nmap XML -> (open ports, [(severity, title, detail)]). Pure function."""
    open_ports, found = [], []
    for port in root.iter("port"):
        st = port.find("state")
        if st is None or st.get("state") != "open":
            continue
        num, proto = int(port.get("portid")), port.get("protocol")
        svc = port.find("service")
        desc = "?"
        if svc is not None:
            desc = " ".join(x for x in (svc.get("name"), svc.get("product"), svc.get("version")) if x)
        open_ports.append({"port": num, "proto": proto, "service": desc})
        sev, why = RISKY.get(num, ("info", ""))
        for rx, bsev, bwhy in BANNER_RISKS:
            if rx.search(desc):
                sev = bsev if SEV_ORDER[bsev] < SEV_ORDER[sev] else sev
                why = (why + "; " if why else "") + bwhy
        found.append((sev, f"Open port {num}/{proto}: {desc}", why))
        for sc in port.findall("script"):
            found += nse.evaluate(sc, f"{num}/{proto}", now)
    for hs in root.iter("hostscript"):
        for sc in hs.findall("script"):
            found += nse.evaluate(sc, "host", now)
    return open_ports, found


def run(ctx) -> ScanResult:
    res = ScanResult("nmap")
    if not valid_host(ctx.rem.host) or not valid_ports(ctx.opts.nmap_ports):
        res.status = "error"
        res.add("info", "Invalid host or ports: nmap scan not performed")
        return res
    if not shutil.which("nmap"):
        return res.skip("nmap not installed on the local machine (e.g. sudo apt install nmap)")

    # -sV detects name and version of the software behind each port (needed for CVEs);
    # -Pn skips the initial ping: many firewalls block it and nmap would report "host down".
    cmd = ["nmap", "-sV", "--version-light", "-Pn", "-T4", "-oX", "-"]
    if ctx.opts.nmap_ports == "-":
        cmd.append("-p-")
    else:
        cmd += ["-p", ctx.opts.nmap_ports] if ctx.opts.nmap_ports else ["--top-ports", "1000"]
    scripts = script_list(ctx.opts)
    if scripts:
        # NSE scripts run only on open ports and only when the service matches
        # (ftp-anon only on FTP...): the cost is a few seconds.
        cmd += ["--script", ",".join(scripts)]
    cmd.append(ctx.rem.host)

    p = subprocess.run(cmd, capture_output=True, text=True, timeout=ctx.opts.scan_timeout)
    res.raw = p.stderr
    try:
        root = ET.fromstring(p.stdout)
    except ET.ParseError:
        res.status = "error"
        res.add("info", "nmap output cannot be parsed", p.stderr[:500])
        return res

    open_ports, found = parse_xml(root)
    for sev, title, detail in found:
        res.add(sev, title, detail)
    res.data["nse"] = script_list(ctx.opts)
    res.data["open_ports"] = open_ports
    if not open_ports:
        res.add("info", "No open port detected from outside")
    return res
