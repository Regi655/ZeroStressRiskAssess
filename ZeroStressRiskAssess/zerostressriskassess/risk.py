"""Risk = Impact x Likelihood on a 5x5 matrix.

A single severity mixes two different questions:
  - IMPACT: if it happens, how bad is it? (what the attacker gains by exploiting the weakness)
  - LIKELIHOOD: how easily can it happen? (who can do it, from where, with what effort)
A weakness granting root but requiring prior administrator access (I=5, L=1 -> 5) ranks below one
granting access to a single service that anyone on the network can reach without a password
(I=3, L=5 -> 15). This follows ISO/IEC 27005 and the OWASP Risk Rating Methodology, reduced to
five levels per axis.

IMPACT derives from the nature of the weakness (rules below, one per finding type).
LIKELIHOOD starts from the same rule (attack vector: network, local account, interception, physical
access) and is ADJUSTED with what the tool actually measured:
  - a network weakness on a port nmap saw open from the controller is left unchanged;
  - if nmap saw the port closed or filtered, likelihood drops by 2 (an attacker must first get into
    the internal network or onto the machine);
  - for CVEs: actively exploited (CISA KEV catalogue) -> 5.
Every value carries its rationale, which is shown in the report table.
"""
from __future__ import annotations

import re

IMPACT = {
    5: ("Total", "full control of the machine (root) or of all its data"),
    4: ("Severe", "root reachable by a local user, credential theft, control of an important service"),
    3: ("Significant", "access to data or to a non-critical service, tampering with application data"),
    2: ("Limited", "information useful for an attack, or a weakened defence"),
    1: ("Minimal", "best practice not followed, no direct damage"),
}
PROBABILITY = {
    5: ("Almost certain", "exploitable by anyone who reaches the machine over the network, without credentials, "
                          "with common tools; or already happening"),
    4: ("Likely", "exploitable from the network with little effort (guessable password, known technique)"),
    3: ("Possible", "requires any account on the machine"),
    2: ("Unlikely", "requires special conditions: traffic interception, physical access, a second flaw"),
    1: ("Rare", "requires being an administrator already, or is theoretical"),
}
LEVELS = [(15, "CRITICAL"), (10, "HIGH"), (5, "MEDIUM"), (1, "LOW")]
VECTOR = {
    "network": "from the network",
    "local": "with an account on the machine",
    "interception": "by intercepting traffic (man-in-the-middle position)",
    "physical": "with physical access to the device or its disks",
    "compromise": "indicator of a compromise that has already happened",
    "admin": "only by someone who is already an administrator",
    "known": "public vulnerabilities already fixed by the vendor: ready-made exploits exist for many of them",
}
SERVICE_PORTS = {"ssh": None, "ftp": 21, "mysql": 3306, "dns": 53, "docker": 2375, "smb": 445}


def level(r: int) -> str:
    return next(name for low, name in LEVELS if r >= low)


# (check, title regex, impact, likelihood, vector, network service or None, remediation)
# The first matching row wins. The service is used to verify exposure against nmap results.
RULES = [
    # --- accounts and access
    ("accounts", r"UID 0", 5, 3, "local", None,
     'Remove UID 0 from every account other than root (usermod -u) or delete the account.'),
    ("accounts", r"empty password|without password \(empty field", 4, 3, "local", None,
     "Set a password (passwd USER) or lock the account (passwd -l USER)."),
    ("accounts", r"DES hash|MD5 hash|password hash stored in /etc/passwd", 4, 2, "local", None,
     "Have the password changed: it will be stored with a modern hash (yescrypt/SHA-512) in /etc/shadow."),
    ("accounts", r"GID 0|UID .* shared|login shell|duplicated|Malformed", 3, 2, "local", None,
     'One UID per person; /usr/sbin/nologin as the shell of service accounts (usermod -s).'),
    ("accounts", r"modified in the last", 2, 1, "admin", None,
     'Verify that the recent account changes were made by authorised people.'),
    ("sudoers", r"Any user|writable|not owned by root|modifiable", 5, 3, "local", None,
     'sudoers files owned by root with mode 0440; rules only for specific users or groups (visudo).'),
    ("sudoers", r"!authenticate|for ALL commands|spawning a shell|LD_PRELOAD|env_reset", 5, 3, "local", None,
     'Remove NOPASSWD/!authenticate and programs that spawn a shell; keep env_reset (visudo).'),
    ("sudoers", r"write arbitrary files|wildcard|setenv|without argument restrictions", 4, 3, "local", None,
     'List the allowed commands with their exact arguments, without * or programs that write files.'),
    ("sudoers", r"can run any command as root", 5, 2, "local", None,
     "Normal for an administrator: verify that the user must be one and uses a strong password."),
    ("sudoers", r"never expires|sudoers permissions|visudo", 3, 2, "local", None,
     'Fix with visudo (positive timestamp_timeout, mode 0440, valid syntax).'),
    ("sshd", r"PermitEmptyPasswords", 5, 2, "network", "ssh",
     'PermitEmptyPasswords no in /etc/ssh/sshd_config, then systemctl reload ssh.'),
    ("sshd", r"PermitRootLogin", 5, 3, "network", "ssh",
     'PermitRootLogin prohibit-password (or no) and log in as a regular user + sudo.'),
    ("sshd", r"PasswordAuthentication", 4, 3, "network", "ssh",
     'Key-only login: PasswordAuthentication no (after copying the keys with ssh-copy-id).'),
    ("sshd", r"rhosts|host-based|PermitUserEnvironment", 4, 2, "network", "ssh",
     'IgnoreRhosts yes, HostbasedAuthentication no, PermitUserEnvironment no.'),
    ("sshd", r"weak", 3, 2, "interception", None,
     'Remove the listed algorithms from Ciphers/MACs/KexAlgorithms; verify with sshd -T and ssh-audit.'),
    ("sshd", r"GatewayPorts|PermitTunnel", 3, 2, "local", None,
     'GatewayPorts no and PermitTunnel no, unless there is a documented need.'),
    ("sshd", r"X11Forwarding|MaxAuthTries|LogLevel", 2, 2, "network", "ssh",
     'X11Forwarding no, MaxAuthTries 3-4, LogLevel INFO or VERBOSE.'),
    ("ssh_audit", r"weak algorithms|discouraged|Terrapin|host key", 3, 2, "interception", None,
     'Update OpenSSH and remove the listed algorithms (guide: ssh-audit.com/hardening_guides.html).'),
    # --- permissions and files
    ("permissions", r"private key", 4, 3, "local", None,
     "chmod 600 on the key; if others could read it, consider it stolen and replace it."),
    ("permissions", r"authorized_keys|add keys", 5, 3, "local", None,
     "chmod 600 authorized_keys, 700 for ~/.ssh, owned by the user; review the keys present."),
    ("permissions", r"[Cc]redentials|password", 4, 3, "local", None,
     'chmod 600 (or 640 with the service group) and change the credentials if exposed.'),
    ("permissions", r"shell or an interpreter|Interpreter or shell|MODIFIED", 5, 3, "local", None,
     "Remove SUID/capability (chmod u-s / setcap -r) and investigate who set it."),
    ("permissions", r"SUID.*(not owned|where it should not|outside packages)|chrome-sandbox", 5, 3, "local", None,
     "Remove the SUID bit (chmod u-s) or the file if not needed; verify its origin."),
    ("permissions", r"Root-equivalent capability.*outside|reads ANY", 4, 3, "local", None,
     'Remove the capability (setcap -r FILE) unless essential.'),
    ("permissions", r"SUID|Capability|cap_", 3, 2, "local", None,
     'Verify that the program is needed; otherwise chmod u-s / setcap -r.'),
    ("permissions", r"System file writable|belongs to UID|owner .* instead of root", 5, 3, "local", None,
     "chown root:root and chmod o-w on the file; verify its integrity (dpkg -V)."),
    ("permissions", r"missing sticky|Home directory .* writable by everyone|without sticky bit", 4, 3, "local", None,
     'chmod o-w on the directory (or chmod +t if it must remain shared, like /tmp).'),
    ("permissions", r"permissions too wide|writable|by the group", 3, 3, "local", None,
     'Reduce the permissions to the minimum needed (chmod o-w, g-w).'),
    # --- persistence and integrity: indicators, not weaknesses
    ("persistence", r"ld\.so\.preload", 5, 5, "compromise", None,
     "Investigate immediately: /etc/ld.so.preload loads libraries into every program (a typical rootkit technique)."),
    ("persistence", r"authorized_keys", 4, 3, "local", None,
     "Verify who owns each authorised key and remove the ones not recognised."),
    ("integrity", r"Binary hash|Binary modified|PID .* NOT shown|INFECTED", 5, 5, "compromise", None,
     'Isolate the machine and investigate: a tampered system command is an indicator of compromise.'),
    ("integrity", r"temporary directory|shadowed|deleted from disk", 5, 4, "compromise", None,
     'Identify the process (ls -l /proc/PID/exe, cmdline) and how it starts; stop it if not recognised.'),
    ("integrity", r"not owned by root|writable by everyone", 5, 3, "local", None,
     'chown root and chmod o-w on the command; reinstall the package (apt install --reinstall).'),
    ("services", r"binary", 3, 2, "local", None,
     "Verify the program outside packages: who installed it, from where, whether it is needed."),
    ("clamav", r"EICAR", 1, 1, "admin", None,
     'No action: it is the antivirus test file. Remove it when no longer needed.'),
    ("clamav", r"ClamAV: ", 5, 5, "compromise", None,
     'Quarantine the file, find out how it arrived, review processes and logins.'),
    # --- network and services
    ("firewall", r"services reachable", 3, 4, "network", "port",
     'Enable a firewall (ufw default deny incoming; ufw allow ssh) and open only the required ports.'),
    ("firewall", r"BYPASS", 3, 4, "network", None,
     'Publish container ports on 127.0.0.1 or filter in the DOCKER-USER chain.'),
    ("firewall", r"No active firewall", 2, 3, "network", None,
     'Enable ufw: ufw default deny incoming, ufw allow OpenSSH, ufw enable.'),
    ("containers", r"Docker API listening on the network WITHOUT", 5, 5, "network", "docker",
     'Remove -H tcp:// from the Docker daemon or use --tlsverify with client certificates.'),
    ("containers", r"writable by ANYONE|docker group", 5, 3, "local", None,
     'Remove from the docker group whoever must not be an administrator (gpasswd -d USER docker).'),
    ("containers", r"Privileged container|Docker socket mounted|mounted in the container|dangerous capabilities", 5, 2,
     "local", None,
     'Recreate the container without --privileged, without the socket or system directories mounted, without cap-add.'),
    ("containers", r"BYPASS", 3, 4, "network", None,
     'Publish container ports on 127.0.0.1 or filter in the DOCKER-USER chain.'),
    ("containers", r"shares with the host|unusual group", 3, 2, "local", None,
     "Avoid --network host / --pid host unless needed; Docker socket owned by the docker group."),
    ("dns", r"OPEN resolver|recursion granted", 3, 5, "network", "dns",
     'allow-recursion { internal networks; }; (BIND) or access-control (Unbound) for authorised clients only.'),
    ("dns", r"zone transfer", 2, 5, "network", "dns",
     'allow-transfer { secondary servers; }; in the options of named.conf.'),
    ("dns", r"authoritative and a recursive resolver|DNSSEC|rate limiting", 3, 2, "network", "dns",
     'Separate authoritative and resolver; dnssec-validation auto; rate-limit on authoritative servers.'),
    ("dns", r"version", 1, 5, "network", "dns",
     'version "not available"; (BIND) or hide-version: yes (Unbound).'),
    ("mysql", r"skip-grant-tables", 5, 4, "network", "mysql",
     'Remove skip-grant-tables from the configuration and restart MySQL immediately.'),
    ("mysql", r"WITHOUT password|ANONYMOUS", 5, 4, "network", "mysql",
     "A password for every account; remove anonymous accounts (DROP USER ''@'host')."),
    ("mysql", r"root usable", 5, 3, "network", "mysql",
     "root from localhost only: DROP USER 'root'@'%' and a dedicated administrative account."),
    ("mysql", r"ANY host", 3, 3, "network", "mysql",
     "Restrict the account host to the application servers' addresses."),
    ("mysql", r"reachable from the controller", 3, 4, "network", "mysql",
     'bind-address = 127.0.0.1 (or an internal address) and a firewall allowing only the application servers.'),
    ("mysql", r"password .*readable", 5, 3, "local", None,
     'chmod 600 on the file containing the database password.'),
    ("mysql", r"FILE privilege", 4, 2, "local", None,
     "REVOKE FILE ON *.* FROM the account: applications rarely need it."),
    ("mysql", r"without TLS|TLS available", 3, 2, "interception", None,
     'Enable TLS (certificates) and require_secure_transport=ON.'),
    ("mysql", r"SUPER|local_infile|secure_file_priv|database 'test'|not authorised", 2, 2, "local", None,
     "local_infile=0, secure_file_priv on a dedicated directory, drop the test database, SUPER for administrators only."),
    ("ftp", r"anonymous user can WRITE", 4, 5, "network", "ftp",
     'anon_upload_enable=NO and anon_mkdir_write_enable=NO (or anonymous_enable=NO) in vsftpd.conf.'),
    ("ftp", r"[Aa]nonymous", 2, 5, "network", "ftp",
     "anonymous_enable=NO in vsftpd.conf, unless anonymous FTP is intended."),
    ("ftp", r"clear-text passwords", 4, 2, "interception", None,
     'Use SFTP (already provided by SSH) or enable FTPS: ssl_enable=YES in vsftpd.'),
    ("ftp", r"not confined", 2, 3, "local", None,
     'chroot_local_user=YES in vsftpd.conf.'),
    ("nmap", r"Redis answers WITHOUT a password|Heartbleed|SSLv2|Docker API", 5, 5, "network", "port",
     "Block network access immediately (bind 127.0.0.1 / firewall) and update or configure authentication."),
    ("nmap", r"Git repository|WRITABLE", 4, 5, "network", "port",
     "Deny access to .git in the web server (or remove it from the published directory)."),
    ("nmap", r"Memcached|Anonymous FTP", 3, 5, "network", "port",
     "Restrict the service to 127.0.0.1 or the internal network; disable anonymous access."),
    ("nmap", r"HTTP methods", 2, 3, "network", "port",
     'Disable PUT, DELETE and TRACE in the web server if not needed.'),
    ("nmap", r"Certificate|TLS|SSLv3|Diffie-Hellman|POODLE|CCS|Ciphers|SMB", 3, 2, "interception", None,
     'Renew certificates, allow only TLS 1.2/1.3 and modern ciphers (guide: ssl-config.mozilla.org); require SMB signing.'),

    # --- system
    ("hardening", r"randomize_va_space|protected_symlinks|protected_hardlinks", 4, 2, "local", None,
     'Restore the expected value with a file in /etc/sysctl.d/ and sysctl --system.'),
    ("hardening", r"source_route", 3, 2, "interception", None,
     'net.ipv4.conf.all.accept_source_route=0 in /etc/sysctl.d/.'),
    ("hardening", r"weak hash|UMASK", 3, 2, "local", None,
     'ENCRYPT_METHOD YESCRYPT (or SHA512) and UMASK 022/027 in /etc/login.defs.'),
    ("hardening", r"promiscuous", 4, 4, "compromise", None,
     'Identify which program captures all traffic; if not intended, investigate.'),
    ("hardening", r"Kernel parameters|mounted without|auditd|clock", 2, 2, "local", None,
     'Baseline hardening: recommended sysctl values, nodev/nosuid/noexec on /dev/shm, auditd, chrony/timesyncd.'),
    ("platform", r"NOT encrypted", 4, 2, "physical", None,
     'Disk encryption (LUKS): chosen at installation; on a laptop it is the main defence against theft.'),
    ("platform", r"Swap NOT encrypted", 3, 2, "physical", None,
     'Encrypt swap (crypttab with a random key) or use zram.'),
    ("platform", r"Secure Boot DISABLED|BIOS", 4, 1, "physical", None,
     'Enable Secure Boot in the firmware (UEFI).'),
    ("updates", r"security updates not installed", 4, 3, "known", None,
     'sudo apt update && sudo apt upgrade; then restart the services or the machine if required.'),
    ("updates", r"Reboot required", 3, 2, "known", None,
     'Reboot at an agreed time to load the updated kernel and libraries.'),
    ("updates", r"non-security", 2, 2, "local", None,
     'sudo apt update && sudo apt upgrade (not urgent: they fix bugs, not vulnerabilities).'),
    ("updates", r"[Aa]utomatic|held back|still running", 2, 2, "local", None,
     'sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades.'),
    ("lynis", r".", 2, 2, "local", None, "See the Lynis ID given in the finding (cisofy.com/lynis/controls/ID)."),
]
RULES = [(s, re.compile(rx), i, p, v, svc, fx) for s, rx, i, p, v, svc, *fxl in RULES if i
         for fx in [fxl[0] if fxl else ""]]
# nmap "open port N/tcp": the risk depends on the service. (ports, impact, likelihood)
PORT_RULES = [
    ({23, 512, 513, 514}, 5, 4, "Disable telnet and the r* services: use SSH."),
    ({1337, 4444, 5555, 12345, 31337}, 5, 4, "Identify the listening process (ss -tlnp) and investigate: typical "
                                             "backdoor port."),
    ({2375}, 5, 5, "Close the Docker API on the network or protect it with TLS and client certificates."),
    ({6379, 27017, 9200, 11211}, 4, 4, "Listen on 127.0.0.1 or the internal network only, enable authentication, firewall."),
    ({445, 139, 135, 3389, 5900}, 4, 3, "Expose file shares and remote desktop only over VPN or the internal network."),
    ({21, 69, 3306, 5432, 1433, 111}, 3, 3, "Restrict the service to the network that needs it (firewall, bind-address)."),
]
PORT_RE = re.compile(r"^Open port (\d+)/")
# No specific rule: the finding severity, already calibrated per check, is mapped to an I x L pair.
FALLBACK = {"critical": (5, 4), "high": (4, 3), "medium": (3, 3), "low": (2, 2), "info": (1, 1)}


def rate_finding(scan: str, f: dict):
    """(impact, likelihood, vector, service, from_rule, remediation)."""
    m = PORT_RE.match(f["title"]) if scan == "nmap" else None
    if m:
        port = int(m.group(1))
        for ports, i, p, fx in PORT_RULES:
            if port in ports:
                return i, p, "network", "port", True, fx
        i, p = FALLBACK.get(f["severity"], (2, 2))
        return i, p, "network", "port", False, ""
    for s, rx, i, p, v, svc, fx in RULES:
        if s == scan and rx.search(f["title"]):
            return i, p, v, svc, True, fx
    i, p = FALLBACK.get(f["severity"], (2, 2))
    return (i, p, "network" if scan in ("nmap", "ssh_audit") else "local", "port" if scan == "nmap" else None,
            False, "")


def _port_of(svc, f: dict, ctx: dict):
    if svc == "port":
        # Several ports in the title (e.g. firewall: "2024/tcp, 2025/tcp, 21/tcp"): the reachable one counts,
        # if any; otherwise the first.
        ports = [int(p) for p in re.findall(r"(\d+)/(?:tcp|udp)", f["title"])]
        seen = [p for p in ports if p in (ctx.get("nmap") or ())]
        return (seen or ports or [None])[0]
    if svc == "ssh":
        return ctx.get("ssh_port", 22)
    if svc == "mysql":
        return ctx.get("mysql_port", 3306)
    return SERVICE_PORTS.get(svc)


def exposure(vector, svc, f, ctx: dict):
    """(likelihood adjustment, reason). ctx["nmap"]: None = nmap not run, otherwise the set of ports
    seen open from the controller.
    """
    if vector != "network":
        return 0, VECTOR[vector]
    port = _port_of(svc, f, ctx)
    if ctx.get("nmap") is None:
        return 0, "from the network (exposure not verified from outside: " + ctx.get("why_no_nmap", "nmap not run") + ")"
    if port is None:
        return 0, "from the network"
    if port in ctx["nmap"]:
        return 0, f"from the network: port {port} reachable from the controller"
    return -2, f"port {port} NOT reachable from the controller (firewall or local only): the attacker must first get into the network"


def _group_override(issue: dict, ctx: dict):
    key = issue.get("key") or ""
    if key == "ssh-nopass":
        return 5, 5, "network", "ssh"
    if key == "ftp-anon":
        return (4 if "upload" in issue["title"] else 2), 5, "network", "ftp"
    if key == "dns-axfr":
        return 2, 5, "network", "dns"
    if key == "lynis-tips":
        return 2, 2, "local", None
    if key == "patch":
        return _patch(ctx)
    if key == "port:21":
        # FTP for system users: account passwords sent in clear text and guessable from the network
        return 4, 3, "network", "ftp"
    return None


SEV_IMPACT = {"critical": 5, "high": 4, "medium": 3, "low": 2}


def _patch(ctx: dict):
    """Security updates / fixable CVEs. Impact = most severe CVE; likelihood 5 if a CVE is actively
    exploited (CISA KEV), 4 if a severe network-exploitable one exists (CVSS AV:N), 3 otherwise.
    """
    cves = ctx.get("cve_now") or []
    if not cves:
        return 4, 3, "known", None
    imp = max(SEV_IMPACT.get(c["severity"], 2) for c in cves)
    if any(c.get("kev") for c in cves):
        return imp, 5, "compromise_kev", None
    net = any("AV:N" in "".join(c.get("cvss") or []) and c["severity"] in ("critical", "high") for c in cves)
    return imp, 4 if net else 3, "cve", None


def assess(scans: list, issues: list, ctx: dict) -> list:
    """Add impact, likelihood, risk, level and rationale to every issue. Returns the issues sorted by
    risk (then impact). Pure function.
    """
    by_id = {f["id"]: (sc["name"], f) for sc in scans for f in sc["findings"]}
    out = []
    for issue in issues:
        if issue["severity"] == "info":
            continue
        members = [by_id[e] for e in issue["evidence"] if e in by_id]
        ov = _group_override(issue, ctx)
        if ov:
            i, p, v, svc = ov
            ref = members[0][1] if members else {"title": issue["title"]}
            if v == "compromise_kev":
                delta, why = 0, "actively exploited CVEs (CISA KEV catalogue)"
            elif v == "cve":
                delta, why = 0, ("severe network-exploitable CVEs (CVSS AV:N)" if p == 4
                                 else "known CVEs with an available fix")
            else:
                delta, why = exposure(v, svc, ref, ctx)
            rule = True
        else:
            best = None
            for scan, f in members:
                fi, fp, fv, fsvc, from_rule, fx = rate_finding(scan, f)
                d, w = exposure(fv, fsvc, f, ctx)
                cand = (fi, max(1, fp + d), w, from_rule, fx)
                if best is None or cand[0] * cand[1] > best[0] * best[1] or \
                        (cand[0] * cand[1] == best[0] * best[1] and cand[0] > best[0]):
                    best = cand
            i, p, why, rule, fix = best if best else (2, 2, "", False, "")
            if not issue.get("fix") and fix:
                issue = {**issue, "fix": fix}
            delta = 0
        p = max(1, min(5, p + delta))
        r = i * p
        out.append({**issue, "impact": i, "probability": p, "risk": r, "level": level(r),
                    "impact_why": IMPACT[i][1], "probability_why": why,
                    "estimated": not rule})
    out.sort(key=lambda x: (-x["risk"], -x["impact"], x["id"]))
    return out


def matrix(rated: list) -> dict:
    """{(impact, likelihood): number of issues}."""
    m = {}
    for r in rated:
        m[(r["impact"], r["probability"])] = m.get((r["impact"], r["probability"]), 0) + 1
    return m


def overall(rated: list) -> str:
    return rated[0]["level"] if rated else "LOW"
