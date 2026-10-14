"""nmap NSE scripts: from an open port to the concrete WEAKNESS, as seen from the controller.

nmap -sV reports "port 21 open, vsftpd 3.0.5" but not whether FTP accepts anonymous logins, whether a
directory is world-writable, whether a website exposes its .git directory or whether Redis answers
without a password. NSE scripts ask the service exactly these questions, as an attacker would.

Only scripts in nmap's "safe" category are used: they do not guess passwords, exploit vulnerabilities
or send data that could crash the service. ssl-enum-ciphers belongs to the "intrusive" category (dozens
of TLS connections to enumerate ciphers) and runs only with --nse-tls.

Every parser was validated against REAL nmap 7.94 output from deliberately misconfigured services
(vsftpd, nginx, Redis, memcached, Samba): tests/fixtures/nmap_nse_*.xml.
"""
from __future__ import annotations

import re
from datetime import datetime

SAFE_SCRIPTS = ("ftp-anon", "http-git", "http-methods", "ssl-cert", "sslv2", "ssl-dh-params", "ssl-heartbleed",
                "ssl-poodle", "ssl-ccs-injection", "smb2-security-mode", "redis-info", "memcached-info")
TLS_SCRIPTS = ("ssl-enum-ciphers",)

# Severity of "VULNERABLE" results from scripts based on nmap's vulns library.
VULN_SEV = {"ssl-heartbleed": "critical", "ssl-ccs-injection": "high", "ssl-poodle": "medium",
            "ssl-dh-params": "medium"}
WEAK_GRADES = {"C": "medium", "D": "medium", "E": "high", "F": "high"}


def _elems(node, key=None):
    """Text of the direct <elem> children (with the given key, if any)."""
    return [e.text or "" for e in node.findall("elem") if key is None or e.get("key") == key]


def _table(node, key):
    for t in node.findall("table"):
        if t.get("key") == key:
            return t
    return None


def evaluate(script, where: str, now: datetime = None) -> list:
    """One <script> element of nmap XML -> [(severity, title, detail)]. Pure function.
    where = "21/tcp" for port scripts, "host" for host scripts.
    """
    sid, out = script.get("id"), script.get("output", "")
    found = []

    if sid == "ftp-anon" and "Anonymous FTP login allowed" in out:
        writable = [l.split()[-3] if l.endswith("[NSE: writeable]") else "" for l in out.splitlines()]
        writable = [w for w in writable if w]
        if writable:
            found.append(("high", f"Anonymous FTP with WRITABLE directories ({where}): {', '.join(writable)}",
                          "Anyone can upload files without a password: a drop point for malware or illegal "
                          "material in the name of the server owner. Disable anon_upload_enable."))
        else:
            listing = "" if "Can't get directory listing" not in out else (
                " The file list cannot be read from here (" + out.split("Can't get directory listing:")[-1].strip()[:80]
                + "), so it is NOT possible to tell whether writable directories exist: the ftp check verifies it from inside.")
            found.append(("medium", f"Anonymous FTP allowed ({where})",
                          "Anyone can read the published files without a password. Verify that this is intended and that "
                          "no confidential data is exposed (in vsftpd: anonymous_enable=NO)." + listing))

    elif sid == "http-git":
        for repo in script.findall("table"):
            remotes = _table(repo, "remotes")
            found.append(("high", f"Git repository published by the website ({where}): {repo.get('key')}",
                          "The .git directory exposes the whole source code and its history, often including "
                          "passwords and keys left in old commits. Remote: "
                          + (", ".join(_elems(remotes)) if remotes is not None else "?")))

    elif sid == "http-methods":
        risky = _table(script, "Potentially risky methods")
        if risky is not None and _elems(risky):
            found.append(("low", f"Potentially dangerous HTTP methods advertised ({where}): "
                                 + " ".join(_elems(risky)),
                          "The server LISTS them in the OPTIONS response (Allow header): it does not necessarily "
                          "execute them. PUT/DELETE may allow writing or deleting files; "
                          "TRACE reflects requests (old XST attack). To be confirmed manually."))

    elif sid == "ssl-cert":
        found += _cert(out, where, now or datetime.now())

    elif sid == "sslv2" and "SSLv2 supported" in out:
        found.append(("high", f"SSLv2 enabled ({where})", "Protocol broken since 1996 (DROWN): it must be disabled."))

    elif sid in VULN_SEV:
        for v in script.findall("table"):
            state = " ".join(_elems(v, "state"))
            if "VULNERABLE" in state:
                title = " ".join(_elems(v, "title")) or sid
                checks = _table(v, "check_results")
                detail = " ".join(" ".join(_elems(checks)).split())[:300] if checks is not None else ""
                found.append((VULN_SEV[sid], f"{title} ({where}) [{sid}: {state}]", detail))

    elif sid == "smb2-security-mode":
        if "signing enabled but not required" in out:
            found.append(("medium", "SMB: message signing NOT required",
                          "Enables NTLM relay attacks: an attacker on the network forwards a user's authentication "
                          "to this server. In Samba: server signing = mandatory."))
        elif re.search(r"signing disabled", out, re.I):
            found.append(("high", "SMB: message signing DISABLED", out.strip()[:200]))

    elif sid == "redis-info" and _elems(script, "Version"):
        found.append(("critical", f"Redis answers WITHOUT a password ({where})",
                      f"Version {_elems(script, 'Version')[0]}. Whoever reaches the port reads and writes all data "
                      "and, with CONFIG SET, can write files on the server (a classic way to take "
                      "control of it). Set requirepass (or ACLs) and bind it to 127.0.0.1."))

    elif sid == "memcached-info" and "Authentication" in out and _elems(script, "Authentication")[:1] == ["no"]:
        found.append(("high", f"Memcached reachable without authentication ({where})",
                      "Anyone can read and modify the cache (often containing user sessions). "
                      "Bind it to 127.0.0.1 (-l 127.0.0.1)."))

    elif sid == "ssl-enum-ciphers":
        found += _ciphers(script, where)
    return found


def _cert(out: str, where: str, now: datetime) -> list:
    f, info = [], {}
    for line in out.splitlines():
        k, _, v = line.partition(":")
        info[k.strip()] = v.strip()
    after = info.get("Not valid after", "")
    try:
        exp = datetime.strptime(after[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        exp = None
    if exp and exp < now:
        f.append(("medium", f"TLS certificate EXPIRED ({where}) on {after[:10]}",
                  "Clients show an error: users get used to ignoring it, and it is exactly the error they "
                  "would see during a man-in-the-middle attack."))
    elif exp and (exp - now).days < 30:
        f.append(("low", f"TLS certificate expiring ({where}) on {after[:10]}", ""))
    if info.get("Subject") and info.get("Subject") == info.get("Issuer"):
        f.append(("low", f"Self-signed TLS certificate ({where}): {info['Subject']}",
                  "Clients cannot verify it: acceptable only for internal services with a manually "
                  "distributed certificate."))
    bits = info.get("Public Key bits", "")
    if info.get("Public Key type") == "rsa" and bits.isdigit() and int(bits) < 2048:
        f.append(("medium", f"RSA key of the certificate too short ({where}): {bits} bits", "Minimum 2048."))
    if re.search(r"sha1With|md5With", info.get("Signature Algorithm", ""), re.I):
        f.append(("medium", f"Certificate signed with {info['Signature Algorithm']} ({where})",
                  "SHA-1 and MD5 are no longer accepted for certificate signatures."))
    return f


def _ciphers(script, where: str) -> list:
    f = []
    protos = [t.get("key") for t in script.findall("table")]
    old = [p for p in protos if p in ("SSLv3", "TLSv1.0", "TLSv1.1")]
    if "SSLv3" in old:
        f.append(("high", f"SSLv3 enabled ({where})", "Broken protocol (POODLE): it must be disabled."))
    if [p for p in old if p != "SSLv3"]:
        f.append(("medium", f"Obsolete TLS protocols enabled ({where}): {', '.join(p for p in old if p != 'SSLv3')}",
                  "TLS 1.0 and 1.1 are deprecated (RFC 8996). Keep only TLS 1.2 and 1.3."))
    grade = (_elems(script, "least strength") or [""])[0]
    if grade in WEAK_GRADES:
        f.append((WEAK_GRADES[grade], f"Weak TLS ciphers ({where}): lowest grade {grade}",
                  "The grade is nmap's rating of the weakest cipher offered by the server."))
    return f
