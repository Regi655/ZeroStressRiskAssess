"""Effective SSH server configuration.

SSH is almost always a server's entry point. `sshd -T` prints the EFFECTIVE configuration (main file +
sshd_config.d fragments + defaults), which is what actually applies: reading only /etc/ssh/sshd_config
can be misleading, because a fragment read earlier may change an option and defaults depend on the
version. If sshd -T cannot run, the files are parsed instead (explicit values only; the first value
found wins, as in sshd).
"""
from __future__ import annotations

import re

from ..models import ScanResult

# Algorithms broken or long deprecated. Only these are reported: the default lists of modern
# OpenSSH already contain others (e.g. hmac-sha1) that are not worth flagging.
WEAK_CIPHERS = re.compile(r"(^|,)(3des-cbc|arcfour\d*|blowfish-cbc|cast128-cbc|aes\d+-cbc)(,|$)")
WEAK_MACS = re.compile(r"(^|,)(hmac-md5(-96)?(-etm@openssh.com)?|hmac-sha1-96(-etm@openssh.com)?|hmac-ripemd160)(,|$)")
WEAK_KEX = re.compile(r"(^|,)(diffie-hellman-group1-sha1|diffie-hellman-group-exchange-sha1)(,|$)")


def parse_config(text: str, first_wins: bool = False) -> dict:
    """'key value' lines -> dict with lowercase keys. Pure function."""
    cfg = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        k, _, v = line.partition(" ")
        k = k.lower()
        if k == "match":  # Match sections apply only to certain users/hosts: reading stops there
            break
        if first_wins and k in cfg:
            continue
        cfg[k] = v.strip()
    return cfg


def evaluate(cfg: dict, effective: bool):
    """[(severity, title, detail)] for the configuration. Pure function."""
    out = []
    g = lambda k, d=None: cfg.get(k, d).lower() if cfg.get(k, d) is not None else None  # noqa: E731

    if g("permitemptypasswords") == "yes":
        out.append(("critical", "SSH accepts empty passwords (PermitEmptyPasswords yes)",
                    "Anyone with a passwordless account can log in without a password."))
    if g("permitrootlogin") == "yes":
        out.append(("high", "SSH allows direct root login with a password (PermitRootLogin yes)",
                    "Recommended: 'prohibit-password' or 'no'."))
    if g("hostbasedauthentication") == "yes":
        out.append(("high", "SSH: host-based authentication enabled (HostbasedAuthentication yes)", ""))
    if g("ignorerhosts") == "no":
        out.append(("high", "SSH: .rhosts files are honoured (IgnoreRhosts no)", "Obsolete r* mechanism."))
    if g("permituserenvironment") == "yes":
        out.append(("high", "SSH: users can set environment variables (PermitUserEnvironment yes)",
                    "Allows bypassing restrictions (e.g. LD_PRELOAD)."))
    if g("passwordauthentication") == "yes":
        sev = "medium" if g("permitrootlogin") == "yes" else "low"
        out.append((sev, "SSH accepts password authentication (PasswordAuthentication yes)",
                    "Public keys only are recommended, especially when SSH is reachable from the Internet."))
    if g("gatewayports") in ("yes", "clientspecified"):
        out.append(("medium", f"SSH: GatewayPorts {g('gatewayports')}", "Tunnels can expose ports to the whole network."))
    if g("permittunnel") in ("yes", "point-to-point", "ethernet"):
        out.append(("medium", f"SSH: PermitTunnel {g('permittunnel')}", "Network tunnels allowed."))
    if g("loglevel") in ("quiet", "fatal", "error"):
        out.append(("low", f"SSH: LogLevel {g('loglevel')} too low", "Failed logins would not be logged properly."))
    if g("x11forwarding") == "yes":
        out.append(("low", "SSH: X11Forwarding enabled", "Useful only when remote graphical applications are needed."))
    if g("maxauthtries", "6").isdigit() and int(g("maxauthtries", "6")) > 6:
        out.append(("low", f"SSH: MaxAuthTries {g('maxauthtries')} (above the default of 6)", ""))
    if effective:  # defaults are evaluated only if the effective configuration is known
        for key, rx, label in (("ciphers", WEAK_CIPHERS, "ciphers"), ("macs", WEAK_MACS, "MAC"),
                               ("kexalgorithms", WEAK_KEX, "key exchange")):
            m = rx.findall(cfg.get(key, ""))
            if m:
                out.append(("medium", f"SSH: weak {label} enabled", ", ".join(sorted({x[1] for x in m}))))
    return out


def run(ctx) -> ScanResult:
    res, rem = ScanResult("sshd"), ctx.rem
    if rem.run("command -v sshd >/dev/null").rc != 0:
        return res.skip("SSH server (sshd) not present on the target")
    r = rem.run("sshd -T 2>/dev/null", sudo=True)
    effective = r.rc == 0 and "permitrootlogin" in r.out.lower()
    if effective:
        cfg = parse_config(r.out)
    else:
        txt = rem.run("cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null", sudo=True).out
        # sshd reads the sshd_config.d fragments first (Include at the top) and the first value wins:
        # the order is not guaranteed here, so this is only an approximation.
        cfg = parse_config(txt, first_wins=True)
        res.add("info", "sshd -T cannot run: configuration files parsed (explicit values only, no defaults)")
    res.data["effective"] = effective
    for sev, title, detail in evaluate(cfg, effective):
        res.add(sev, title, detail)
    if not res.findings:
        res.add("info", "SSH configuration without evident problems")
    return res
