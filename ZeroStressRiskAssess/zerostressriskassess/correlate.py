"""Correlation: from FINDINGS to ISSUES, with MITRE ATT&CK and CIS Controls references.

Each check looks at the machine from a different angle, so a single weakness is often reported
several times. Anonymous FTP with uploads, for example, is reported by nmap (ftp-anon), by the ftp
check (configuration) and by the permissions check (world-writable directories under the FTP root):
several findings, one remediation. Counting them separately would overstate the risk and hide how
many things actually need fixing.

Rule: only findings describing the SAME weakness (fixed by the same remediation) or the same attack
chain are grouped. Two different settings of the same service (PermitRootLogin and X11Forwarding)
remain separate issues because they require two remediations. A group takes the severity of its
most severe finding and is counted once.

References are indicative: MITRE ATT&CK (Enterprise) techniques enabled by the weakness and CIS
Controls v8 safeguards that prevent it. They support further reading and mapping to a framework;
they are not a compliance statement.
"""
from __future__ import annotations

import re

from .models import SEVERITIES

ORDER = {s: i for i, s in enumerate(SEVERITIES)}
PORT_RE = re.compile(r"\((\d+)/(?:tcp|udp)\)")

# (check, title regex) -> (MITRE techniques, CIS v8 safeguards). The first matching row wins.
REFS = [
    ("accounts", r"empty password|without password \(empty field", ["T1078.003"], ["5.2"]),
    ("accounts", r"UID 0", ["T1078.003", "T1548"], ["5.4"]),
    ("accounts", r"DES hash|MD5 hash|password hash", ["T1110.002"], ["5.2"]),
    ("accounts", r"GID 0|login shell|UID .* shared", ["T1078.003"], ["5.4"]),
    ("sudoers", r"^(?!Members)", ["T1548.003"], ["5.4"]),
    ("sshd", r"PermitEmptyPasswords", ["T1078.003", "T1021.004"], ["5.2"]),
    ("sshd", r"PermitRootLogin", ["T1110", "T1021.004"], ["5.4"]),
    ("sshd", r"PasswordAuthentication", ["T1110"], ["6.5"]),
    ("sshd", r"weak", ["T1557"], ["3.10"]),
    ("sshd", r"rhosts|host-based|PermitUserEnvironment|GatewayPorts|PermitTunnel", ["T1021.004"], ["4.1"]),
    ("ssh_audit", r"weak algorithms|discouraged|Terrapin|host key", ["T1557"], ["3.10"]),
    ("permissions", r"private key", ["T1552.004"], ["3.3"]),
    ("permissions", r"authorized_keys|add keys", ["T1098.004"], ["3.3"]),
    ("permissions", r"[Cc]redentials|password", ["T1552.001"], ["3.3"]),
    ("permissions", r"SUID|SGID|chrome-sandbox", ["T1548.001"], ["4.1"]),
    ("permissions", r"[Cc]apabilit|cap_", ["T1548"], ["4.1"]),
    ("permissions", r"writable|sticky|permissions", [], ["3.3"]),
    ("persistence", r"ld\.so\.preload", ["T1574.006"], []),
    ("persistence", r"authorized_keys", ["T1098.004"], []),
    ("persistence", r"[Cc]ron", ["T1053.003"], []),
    ("persistence", r"'at'", ["T1053.002"], []),
    ("persistence", r"rc\.local|init\.d", ["T1037.004"], []),
    ("persistence", r"timer|unit|systemd", ["T1543.002"], []),
    ("persistence", r"profil|bashrc", ["T1546.004"], []),
    ("integrity", r"shadowed|resolves to a temporary", ["T1574.007"], []),
    ("integrity", r"[Hh]ash|[Bb]inary modified", ["T1554"], ["10.1"]),
    ("integrity", r"PID|ps ", ["T1014"], ["10.1"]),
    ("integrity", r"[Pp]rocess", ["T1036"], ["10.1"]),
    ("services", r"binary", ["T1543.002"], ["4.1"]),
    ("firewall", r"firewall|BYPASS", [], ["4.4"]),
    ("containers", r"docker group|[Ss]ocket|[Pp]rivileged|mounted|capabilit|shares", ["T1611"], ["5.4"]),
    ("containers", r"Docker API", ["T1610"], ["4.4"]),
    ("containers", r"BYPASS", [], ["4.4"]),
    ("dns", r"OPEN resolver|recursion granted", ["T1498.002"], ["4.8"]),
    ("dns", r"zone transfer", ["T1590.002"], ["3.3"]),
    ("dns", r"version", ["T1592.002"], ["4.1"]),
    ("dns", r"DNSSEC", ["T1557"], ["4.1"]),
    ("mysql", r"ANONYMOUS|WITHOUT password|skip-grant", ["T1078"], ["4.7", "5.2"]),
    ("mysql", r"root usable|ANY host", ["T1078"], ["5.4"]),
    ("mysql", r"FILE|SUPER", [], ["5.4"]),
    ("mysql", r"reachable", ["T1190"], ["4.4"]),
    ("mysql", r"TLS", ["T1040"], ["3.10"]),
    ("mysql", r"password .*readable", ["T1552.001"], ["3.3"]),
    ("mysql", r"local_infile|secure_file_priv|database 'test'", [], ["4.1"]),
    ("ftp", r"nonymous", ["T1105"], ["3.3", "4.8"]),
    ("ftp", r"clear-text", ["T1040"], ["3.10"]),
    ("ftp", r"not confined", [], ["3.3"]),
    ("nmap", r"Anonymous FTP", ["T1105"], ["4.8"]),
    ("nmap", r"Redis|Memcached", ["T1190"], ["4.8"]),
    ("nmap", r"Git repository", ["T1213"], ["3.3"]),
    ("nmap", r"Certificate|TLS|SSLv|Diffie-Hellman|Heartbleed|POODLE|CCS|Ciphers", ["T1557"], ["3.10"]),
    ("nmap", r"SMB", ["T1557.001"], ["4.1"]),
    ("nmap", r"HTTP methods", [], ["4.1"]),
    ("nmap", r"Open port", [], ["4.8"]),
    ("updates", r"security|[Rr]eboot|[Aa]utomatic", ["T1068", "T1190"], ["7.3"]),
    ("hardening", r"randomize_va_space|protected_|unprivileged_bpf|kptr|dmesg|ptrace|Kernel parameters",
     ["T1068"], ["4.1"]),
    ("hardening", r"redirects|source_route|rp_filter|ip_forward|syncookies", ["T1557"], ["4.1"]),
    ("hardening", r"auditd", ["T1562.012"], ["8.2"]),
    ("hardening", r"clock", [], ["8.4"]),
    ("hardening", r"mounted without", [], ["4.1"]),
    ("hardening", r"weak hash|UMASK", ["T1110.002"], ["5.2"]),
    ("hardening", r"promiscuous", ["T1040"], ["10.1"]),
    ("cve", r"CVEs fixed", ["T1068", "T1190"], ["7.3", "7.4"]),
    ("platform", r"NOT encrypted", [], ["3.6"]),
    ("platform", r"Secure Boot|BIOS", ["T1542"], ["4.1"]),
    ("chkrootkit", r"INFECTED|sniffer|promiscuous", ["T1014"], ["10.1"]),
    ("rkhunter", r".", ["T1014"], ["10.1"]),
    ("clamav", r".", [], ["10.1"]),
]
REFS = [(s, re.compile(rx), m, c) for s, rx, m, c in REFS]

FIX = {
    "ftp-anon": "In vsftpd: anonymous_enable=NO. If anonymous FTP is really needed: anon_upload_enable=NO, "
                "anon_mkdir_write_enable=NO and directories with mode 755.",
    "port": "If the service must not be public: listen on 127.0.0.1 or the internal network only, plus a firewall; "
            "if it must be: authentication and encryption.",
    "port:21": "FTP sends passwords in clear text: replace it with SFTP (already provided by SSH) or enable FTPS "
               "(ssl_enable=YES in vsftpd); if it is not needed, disable it.",
    "port:3306": "bind-address = 127.0.0.1 (or the internal address) and a firewall allowing only the application servers.",
    "port:6379": "requirepass (or ACLs) and bind 127.0.0.1 in redis.conf.",
    "port:11211": "-l 127.0.0.1 in the memcached options.",
    "port:2375": "Remove -H tcp:// (or use --tlsverify with client certificates); use the local socket.",
    "ssh-algos": "Remove the listed algorithms from Ciphers/MACs/KexAlgorithms/HostKeyAlgorithms and verify "
                 "with sshd -T and ssh-audit.",
    # Debian/Ubuntu command: risk.localise_fix() turns it into the dnf equivalent on the RHEL family.
    "patch": "Install the available updates (sudo apt update && sudo apt upgrade) and restart the services or "
             "the machine if needed.",
    "lynis-tips": "Configuration improvements, not urgent problems: the list with the Lynis IDs is in the "
                  "lynis section.",
    "dns-axfr": "allow-transfer { secondary server addresses; }; in the options of named.conf (or "
                "allow-transfer { none; }; if there are no secondaries).",
    "sudo": "Review the line shown: remove NOPASSWD and restrict the commands to those needed.",
    "ssh-nopass": "PermitEmptyPasswords no in sshd_config and a password (or passwd -l to lock it) for every "
                  "account without a password.",
}


def refs_for(scan: str, title: str) -> dict:
    for s, rx, mitre, cis in REFS:
        if s == scan and rx.search(title):
            return {"mitre": list(mitre), "cis": list(cis)}
    return {"mitre": [], "cis": []}


def _group_key(scan: str, f: dict, ctx: dict):
    """Key of the weakness the finding belongs to (None = standalone issue)."""
    t = f["title"]
    if scan == "nmap" and t.startswith("Anonymous FTP"):
        return "ftp-anon"
    if scan == "ftp" and "nonymous" in t:
        return "ftp-anon"
    if (scan == "permissions" and ctx.get("ftp_write") and ctx.get("ftp_root")
            and t.startswith("World-writable directory") and f["detail"].startswith(ctx["ftp_root"].rstrip("/") + "/")):
        return "ftp-anon"
    if scan == "nmap":
        m = re.match(r"Open port (\d+)/", t)
        if m and f["severity"] != "info":
            return f"port:{m.group(1)}"
        m = PORT_RE.search(t)
        if m and re.match(r"(Redis|Memcached)", t):
            return f"port:{m.group(1)}"
    if scan == "mysql":
        m = re.search(r"reachable from the controller \(port (\d+)\)", t)
        if m:
            return f"port:{m.group(1)}"
    if scan == "ftp" and "clear-text passwords" in t and "21" in ctx.get("open_ports", ()):
        return "port:21"
    if scan == "containers" and t.startswith("Docker API listening on the network WITHOUT"):
        m = re.search(r":(\d+)", f["detail"])
        return f"port:{m.group(1) if m else '2375'}"
    if (scan == "ssh_audit" and "algorithms" in t and "DEFAULT" not in t) or \
            (scan == "sshd" and re.match(r"SSH: weak (ciphers|MAC|key exchange) enabled", t)):
        return "ssh-algos"
    if (scan == "updates" and "security updates not installed" in t) or (scan == "cve" and "CVEs fixed" in t):
        return "patch"   # same remediation: install the available updates
    if scan == "lynis" and f["severity"] == "low":
        return "lynis-tips"   # generic hardening suggestions: a single entry in the issue list
    if scan == "dns" and "zone transfer of" in t:
        return "dns-axfr"   # one zone or ten: the same allow-transfer line is missing
    if scan == "sudoers" and re.match(r"/\S+: ", f["detail"]):
        return "sudo:" + f["detail"]   # several findings on the SAME sudoers line = one remediation
    if (scan == "accounts" and re.search(r"empty password|without password \(empty field", t)) or \
            (scan == "sshd" and "PermitEmptyPasswords" in t):
        return "ssh-nopass"
    return None


def _group_title(key: str, members: list) -> str:
    if key == "ftp-anon":
        write = any("WRITE" in f["title"] for _, f in members)
        return "Anonymous FTP" + (" with file upload by anyone" if write else "")
    if key.startswith("port:"):
        port = key.split(":")[1]
        svc = next((f["title"].split(": ", 1)[1] for s, f in members
                    if s == "nmap" and f["title"].startswith("Open port") and ": " in f["title"]), "")
        return f"Network-exposed service on port {port}" + (f" ({svc})" if svc else "")
    if key == "ssh-algos":
        return "Weak SSH algorithms enabled"
    if key == "patch":
        n = sum(1 for s, _ in members if s == "cve")
        return "Security updates not installed" + (f" ({n} packages with fixable known CVEs)" if n else "")
    if key == "lynis-tips":
        return f"Lynis hardening suggestions ({len(members)})"
    if key == "dns-axfr":
        zones = [re.search(r"of '([^']+)'", f["title"]).group(1) for _, f in members
                 if re.search(r"of '([^']+)'", f["title"])]
        return f"DNS: zone transfer (AXFR) allowed to anyone: {', '.join(zones)}"
    if key.startswith("sudo:"):
        worst = min(members, key=lambda m: ORDER[m[1]["severity"]])[1]
        return f"{worst['title']} ({key[5:].split(': ', 1)[-1]})"
    if key == "ssh-nopass":
        users = [re.search(r"'([^']+)'", f["title"]).group(1) for s, f in members
                 if s == "accounts" and re.search(r"'([^']+)'", f["title"])]
        return "SSH login without password" + (f" (accounts: {', '.join(users)})" if users else "")
    return key


def analyze(scans: list) -> list:
    """Annotate every finding with "refs" and "issue" and return the list of issues.
    scans = report["scans"] (dicts, with the F001... IDs already assigned). Pure function.
    """
    by = {sc["name"]: sc for sc in scans}
    ctx = {"open_ports": {str(p.get("port")) for p in by.get("nmap", {}).get("data", {}).get("open_ports", [])},
           "ftp_root": by.get("ftp", {}).get("data", {}).get("anon_root", ""),
           "ftp_write": any("WRITE" in f["title"] for f in by.get("ftp", {}).get("findings", []))}
    groups, singles = {}, []
    for sc in scans:
        for f in sc["findings"]:
            if f["severity"] == "info":
                # Informational findings are not weaknesses: no attack techniques or safeguards are attached.
                f["refs"] = {"mitre": [], "cis": []}
                continue
            f["refs"] = refs_for(sc["name"], f["title"])
            key = _group_key(sc["name"], f, ctx)
            if key:
                groups.setdefault(key, []).append((sc["name"], f))
            else:
                singles.append((sc["name"], f))
    # A "group" with a single finding is not a group: it becomes a standalone issue.
    for key in [k for k, v in groups.items() if len(v) == 1]:
        singles += groups.pop(key)

    issues = []
    for key, members in groups.items():
        sev = min((f["severity"] for _, f in members), key=ORDER.get)
        issues.append({"title": _group_title(key, members), "severity": sev, "key": key,
                       "evidence": [f["id"] for _, f in members], "scans": sorted({s for s, _ in members}),
                       "fix": FIX.get(key) or FIX.get(key.split(":")[0], ""),
                       "refs": _union(f["refs"] for _, f in members)})
    # Same check, severity and title (e.g. three "world-writable directory without sticky bit"):
    # same weakness and remediation on different objects -> one issue with several pieces of evidence.
    same = {}
    for scan, f in singles:
        # Same title with different severities (e.g. a 777 directory in /opt rated high and one in /var
        # rated medium): same weakness and remediation, one issue with the highest severity.
        same.setdefault((scan, f["title"]), []).append(f)
    for (scan, title), fs in same.items():
        sev = min((f["severity"] for f in fs), key=ORDER.get)
        issues.append({"title": title, "severity": sev, "key": None, "evidence": [f["id"] for f in fs],
                       "scans": [scan], "fix": "", "refs": fs[0]["refs"]})
    for i in issues:
        i["exposed"] = _exposed(i)
    issues.sort(key=lambda i: (ORDER[i["severity"]], not i["exposed"], -len(i["evidence"]), i["evidence"][0]))
    for n, i in enumerate(issues, 1):
        i["id"] = f"P{n:02d}"
    ids = {fid: i["id"] for i in issues for fid in i["evidence"]}
    for sc in scans:
        for f in sc["findings"]:
            if f["id"] in ids:
                f["issue"] = ids[f["id"]]
    return issues


NETWORK_SCANS = {"nmap", "ssh_audit"}


def _exposed(issue: dict) -> bool:
    """Was the weakness OBSERVED FROM THE CONTROLLER over the network? True for nmap and ssh-audit evidence,
    for services grouped by port and for direct evidence ("reachable from the controller", "from the controller"
    in dns and mysql titles). A weakness reachable from outside can be exploited by anyone on that
    network; a local one first requires access to the machine.
    """
    return bool(NETWORK_SCANS & set(issue["scans"])) or str(issue.get("key") or "").startswith("port:") \
        or "from the controller" in issue["title"]


def _union(refs) -> dict:
    out = {"mitre": [], "cis": []}
    for r in refs:
        for k in out:
            out[k] += [x for x in r.get(k, []) if x not in out[k]]
    return out
