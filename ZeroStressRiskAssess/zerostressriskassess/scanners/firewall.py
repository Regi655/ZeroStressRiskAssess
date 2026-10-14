"""Local firewall status (ufw, firewalld, nftables, iptables).

A host firewall is the second line of defence: if a service is started by mistake (or by an
attacker), the rules decide who can reach it. Lynis only reports "iptables without rules"; here all
common frameworks are inspected and the issue is weighted by how many ports actually listen on
the network.

Limitation: the presence of rules and policies is verified, not the quality of each rule.
"""
from __future__ import annotations

import re

from ..models import ScanResult
from .listeners import parse_ss

# CLIENT sockets, not services: the DHCP client listens on 68/udp (IPv4) and 546/udp (IPv6) to
# receive the server's reply. They are not reachable services requiring protection.
CLIENT_PORTS = {(68, "udp"), (546, "udp")}

NFT_RULE = re.compile(r"^\s+(?!type |policy |chain |set |map |elements|flags |\}|#)\S.*\b(accept|drop|reject|jump|goto|dnat|snat|masquerade|redirect|return|counter)\b")


def parse_iptables(text: str):
    """From `iptables -S` -> (number of -A rules, INPUT policy). Pure function."""
    rules, pol = 0, None
    for line in text.splitlines():
        if line.startswith("-A "):
            rules += 1
        m = re.match(r"-P INPUT (\w+)", line)
        if m:
            pol = m.group(1)
    return rules, pol


def parse_nft(text: str):
    """From `nft list ruleset` -> (number of rules, drop policies on the input hook)."""
    rules = sum(1 for l in text.splitlines() if NFT_RULE.match(l))
    drop_in = bool(re.search(r"hook input[^;]*;\s*policy (drop|reject)", text))
    return rules, drop_in


def run(ctx) -> ScanResult:
    res, rem = ScanResult("firewall"), ctx.rem
    active, notes = [], []

    ufw = rem.run("command -v ufw >/dev/null && ufw status 2>&1", sudo=True)
    if ufw.rc == 0 and re.search(r"Status:\s*active", ufw.out, re.I):
        active.append("ufw")
    elif ufw.rc == 0:
        notes.append("ufw installed but inactive")

    if rem.run("systemctl is-active firewalld 2>/dev/null | grep -qx active").rc == 0:
        active.append("firewalld")

    nft = rem.run("command -v nft >/dev/null && nft list ruleset 2>/dev/null", sudo=True)
    if nft.rc == 0:
        n, drop = parse_nft(nft.out)
        if n > 0 or drop:
            active.append(f"nftables ({n} rules)")

    ipt = rem.run("command -v iptables >/dev/null && iptables -S 2>/dev/null", sudo=True)
    if ipt.rc == 0:
        n, pol = parse_iptables(ipt.out)
        res.data["iptables_input_policy"] = pol
        if n > 0 or pol in ("DROP", "REJECT"):
            active.append(f"iptables ({n} rules, INPUT {pol})")

    res.data["active"] = active
    if active:
        res.add("info", "Active firewall: " + ", ".join(active), "; ".join(notes))
        return res

    # No firewall with rules: the severity depends on which ports are reachable.
    socks = parse_ss(rem.run("ss -tuln 2>/dev/null").out)
    ports = sorted({f"{s['port']}/{s['proto']}" for s in socks
                    if not s["loopback"] and (s["port"], s["proto"]) not in CLIENT_PORTS | {(22, "tcp")}})
    detail = ("No rules in ufw/firewalld/nftables/iptables. " + "; ".join(notes)).strip()
    if ports:
        res.add("high", "No active firewall and services reachable besides SSH: " + ", ".join(ports[:15]), detail)
    elif not socks:
        res.add("medium", "No active firewall (listening ports cannot be determined)", detail)
    else:
        res.add("medium", "No active firewall (only SSH listens on the network)",
                detail + " If a service starts by mistake, it will be reachable immediately.")
    return res
