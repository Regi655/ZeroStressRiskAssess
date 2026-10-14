"""ssh-audit from the controller: which algorithms the SSH server ACTUALLY offers to clients.

This complements the sshd check (which reads the configuration from inside):
  - it is the external view, like nmap: what the server negotiates counts, not what is written in a
    file (a forgotten Include, a second sshd on another port...);
  - ssh-audit knows why each algorithm is weak (broken SHA-1, 1024-bit modulus, Terrapin...).

Calibration: copying ssh-audit's verdict is not enough. On a fresh Ubuntu OpenSSH 9.6 server,
ssh-audit 3.9 marks some DEFAULT algorithms as "fail" for policy reasons ("suspected" NIST curves,
hmac-sha1-etm) and nearly all key exchanges as "warn" ("no post-quantum protection"). Reporting them
as medium would give every server the same medium finding. Therefore:
  - algorithm flagged and NOT among OpenSSH defaults -> someone enabled it deliberately:
    medium (fail) or low (warn);
  - algorithm flagged but default -> a single info line "hardening beyond defaults".
The check does not try passwords and opens about ten connections: verified that fail2ban 1.0.2 (sshd
filter, normal/aggressive/ddos modes) does NOT count them as failed attempts.
"""
from __future__ import annotations

import json
import shutil
import subprocess

from ..models import ScanResult
from ..validate import valid_host

# Algorithms enabled by default in OpenSSH 8.x-10.x (sshd_config man page, defaults of KexAlgorithms,
# Ciphers, MACs, HostKeyAlgorithms). The RHEL 9 DEFAULT crypto policies are a subset of these.
OPENSSH_DEFAULTS = {
    "kex": {"mlkem768x25519-sha256", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com",
            "curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521", "diffie-hellman-group-exchange-sha256", "diffie-hellman-group16-sha512",
            "diffie-hellman-group18-sha512", "diffie-hellman-group14-sha256", "ext-info-s",
            "kex-strict-s-v00@openssh.com"},
    "enc": {"chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com",
            "aes256-gcm@openssh.com"},
    "mac": {"umac-64-etm@openssh.com", "umac-128-etm@openssh.com", "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-512-etm@openssh.com", "hmac-sha1-etm@openssh.com", "umac-64@openssh.com",
            "umac-128@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"},
    "key": {"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
            "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com", "rsa-sha2-512", "rsa-sha2-256"},
}
LABEL = {"kex": "key exchange", "enc": "ciphers", "mac": "MAC", "key": "host keys"}


def evaluate(d: dict) -> list:
    """JSON from `ssh-audit -j` -> [(severity, title, detail)]. Pure function."""
    out = []
    banner = (d.get("banner") or {}).get("raw", "?")
    fail, warn, stock, terrapin, short_key = {}, {}, [], [], []
    for cat in ("kex", "key", "enc", "mac"):
        for a in d.get(cat) or []:
            name, notes = a.get("algorithm", "?"), a.get("notes") or {}
            fails, warns = notes.get("fail") or [], notes.get("warn") or []
            if any("Terrapin" in n for n in fails + warns):
                terrapin.append(name)
            if cat == "key" and any("modulus" in n for n in fails):
                short_key.append(f"{name} ({a.get('keysize', '?')} bit)")
                continue
            if not fails and not warns:
                continue
            if name in OPENSSH_DEFAULTS[cat]:
                stock.append(name)
            elif fails:
                fail.setdefault(cat, []).append(f"{name} ({fails[0]})")
            else:
                warn.setdefault(cat, []).append(f"{name} ({warns[0]})")

    def lines(groups):
        return "; ".join(f"{LABEL[c]}: {', '.join(v)}" for c, v in groups.items())

    if fail:
        out.append(("medium", "SSH: weak algorithms enabled in the configuration (ssh-audit)",
                    lines(fail) + ". They are not among OpenSSH defaults: someone added them, "
                    "usually for an old client. Remove them from Ciphers/MACs/KexAlgorithms/HostKeyAlgorithms."))
    if warn:
        out.append(("low", "SSH: discouraged algorithms enabled in the configuration (ssh-audit)", lines(warn)))
    if short_key:
        out.append(("medium", "SSH: host key too short", ", ".join(short_key) + ". Regenerate it (RSA at least 3072 bits, "
                    "or ed25519)."))
    if terrapin:
        out.append(("medium", "SSH vulnerable to Terrapin (CVE-2023-48795)",
                    "The server does not support 'strict' key exchange and offers: " + ", ".join(sorted(set(terrapin)))
                    + ". Update OpenSSH (>= 9.6 or the distribution's patched version)."))
    if stock:
        out.append(("info", f"ssh-audit: {len(stock)} DEFAULT algorithms flagged as improvable",
                    ", ".join(sorted(set(stock))) + ". Hardening beyond the defaults (e.g. the "
                    "ssh-audit.com guides): useful, but not a misconfiguration."))
    out.append(("info", f"SSH server: {banner}", ""))
    return out


def targets(ctx) -> list:
    """Port used for the connection plus any other SSH services seen by nmap (at most 3)."""
    ports = [int(getattr(ctx.rem, "port", 22) or 22)]
    for p in ctx.cache.get("nmap_open", []):
        if str(p.get("service", "")).startswith("ssh") and p.get("port") not in ports:
            ports.append(p["port"])
    return ports[:3]


def run(ctx) -> ScanResult:
    res = ScanResult("ssh_audit")
    if not valid_host(ctx.rem.host):
        return res.skip("Invalid host")
    exe = shutil.which("ssh-audit")
    if not exe:
        return res.skip("ssh-audit not installed on the controller (sudo apt install ssh-audit, or "
                        "pipx install ssh-audit)")
    for port in targets(ctx):
        # --skip-rate-test: the DHEat test opens dozens of connections per second; it resembles a denial of
        # service attack and may trigger the target's defences.
        p = subprocess.run([exe, "-j", "--skip-rate-test", "-t", "10", "-p", str(port), ctx.rem.host],
                           capture_output=True, text=True, timeout=300)
        try:
            d = json.loads(p.stdout)
        except ValueError:
            res.add("info", f"ssh-audit: no SSH answer on port {port}", (p.stderr or p.stdout)[:200])
            continue
        res.data.setdefault("ports", []).append(port)
        for sev, title, detail in evaluate(d):
            res.add(sev, title + (f" [port {port}]" if port != 22 else ""), detail)
    return res
