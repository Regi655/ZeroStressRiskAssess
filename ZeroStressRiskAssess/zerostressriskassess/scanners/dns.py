"""DNS servers: which software, which role, and the typical risks of that role.

The role matters because the same BIND can be:
  - AUTHORITATIVE (publishes the zones of a domain): the typical risk is an open zone transfer,
    which hands out every name, including internal ones;
  - RESOLVER (resolves names for its clients): the typical risk is answering ANYONE (open
    resolver), which is abused for amplification attacks;
  - both at once, which is a design flaw in itself (providers keep them separate).

Two complementary sources:
  1) INSIDE the target: who listens on port 53 and its configuration (what is ALLOWED);
  2) OUTSIDE, from the controller (dnsprobe.py): what the server actually DOES towards us. The
     configuration may contain includes, views and defaults that are not visible: the external
     probe is the observed fact.

The external probe reflects the controller's position: if the controller sits in the authorised
client network, recursion "open" to it is expected. The report says so, and the severity takes
into account what the configuration allows.
"""
from __future__ import annotations

import re
import shlex

from .. import dnsprobe
from ..models import ScanResult

# Recognised DNS programs -> (display name, base role)
DAEMONS = {"named": ("BIND", None), "unbound": ("Unbound", "resolver"), "dnsmasq": ("dnsmasq", "forwarder"),
           "pdns_server": ("PowerDNS Authoritative", "authoritative"), "pdns_recursor": ("PowerDNS Recursor", "resolver"),
           "knotd": ("Knot DNS", "authoritative"), "nsd": ("NSD", "authoritative"),
           "systemd-resolve": ("systemd-resolved", "local resolver")}
# Zones BIND defines as "master" BY DEFAULT (Debian/Ubuntu, RHEL): they do not make a server authoritative.
BUILTIN_ZONES = {".", "localhost", "localhost.localdomain", "127.in-addr.arpa", "0.in-addr.arpa",
                 "255.in-addr.arpa", "1.0.0.127.in-addr.arpa",
                 "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"}
LOOPBACK_RE = re.compile(r"^(127\.|\[?::1\]?$|::1$)")
MAX_AXFR_ZONES = 10


# ---------------------------------------------------------------------------- who listens on port 53
def dns_listeners(ss_out: str) -> dict:
    """From `ss -Htulpn` to {process: {"pid": pid, "addrs": {addresses}}} for port 53. Pure function."""
    out = {}
    for line in ss_out.splitlines():
        p = line.split()
        if len(p) < 5:
            continue
        local = p[4]
        addr, _, port = local.rpartition(":")
        if port != "53":
            continue
        for name, pid in re.findall(r'\("([^"]+)",pid=(\d+)', line):
            d = out.setdefault(name, {"pid": int(pid), "addrs": set()})
            d["addrs"].add(addr.split("%")[0])
    return out


def port53_addrs(ss_out: str) -> set:
    """All addresses listening on port 53, EVEN without the process name. Pure function."""
    out = set()
    for line in ss_out.splitlines():
        p = line.split()
        if len(p) >= 5 and p[4].rpartition(":")[2] == "53":
            out.add(p[4].rpartition(":")[0].split("%")[0])
    return out


def from_ps(ps_out: str, addrs: set) -> dict:
    """Fallback when `ss -p` does not show processes: in a Docker container root lacks CAP_SYS_PTRACE and
    cannot see sockets of processes owned by OTHER users (named runs as 'bind'). `ps` still lists
    them: if a known DNS program is running and something listens on port 53, it is that program.
    Verified by reproducing the case with `capsh --drop=cap_sys_ptrace`. Pure function.
    """
    out = {}
    for line in ps_out.splitlines():
        p = line.split(None, 1)
        if len(p) == 2 and p[0].isdigit() and p[1].strip() in DAEMONS and p[1].strip() != "systemd-resolve":
            out.setdefault(p[1].strip(), {"pid": int(p[0]), "addrs": set(addrs), "from_ps": True})
    return out


def exposed(addrs) -> bool:
    return any(not LOOPBACK_RE.match(a) for a in addrs)


# ---------------------------------------------------------------------------- BIND
TOKEN_RE = re.compile(r'"(?:[^"\\]|\\.)*"|[{};]|[^\s{};"]+')


def parse_named(text: str) -> list:
    """named.conf grammar (output of `named-checkconf -p`) -> statement tree.
    Each statement: {"w": [words], "b": [block statements] or None}. Pure function.
    """
    tokens = TOKEN_RE.findall(text)
    pos = 0

    def block():
        nonlocal pos
        stmts, words = [], []
        while pos < len(tokens):
            t = tokens[pos]
            pos += 1
            if t == "}":
                return stmts
            if t == ";":
                if words:
                    stmts.append({"w": words, "b": None})
                words = []
            elif t == "{":
                stmts.append({"w": words, "b": block()})
                words = []
            else:
                words.append(t.strip('"'))
        if words:
            stmts.append({"w": words, "b": None})
        return stmts

    return block()


def _get(stmts, name):
    return next((s for s in stmts or [] if s["w"] and s["w"][0] == name), None)


def _acl(stmt):
    """Items of a list such as allow-transfer { any; }; None if the statement is absent."""
    if stmt is None:
        return None
    return [" ".join(x["w"]) for x in stmt["b"] or []]


def bind_facts(text: str) -> dict:
    """Security-relevant settings from a BIND configuration. Pure function."""
    tree = parse_named(text)
    opts = (_get(tree, "options") or {}).get("b") or []
    rec = _get(opts, "recursion")
    zones = []
    containers = [tree] + [v["b"] for v in tree if v["w"] and v["w"][0] == "view" and v["b"]]
    for cont in containers:
        for z in cont:
            if not (z["w"] and z["w"][0] == "zone" and len(z["w"]) > 1 and z["b"] is not None):
                continue
            name = z["w"][1].rstrip(".") or "."
            ztype = (_get(z["b"], "type") or {"w": ["", "?"]})["w"][1]
            if name in BUILTIN_ZONES or ztype in ("hint", "forward", "stub", "redirect", "static-stub"):
                continue
            zt = _acl(_get(z["b"], "allow-transfer"))
            zones.append({"name": name, "type": {"master": "primary", "slave": "secondary"}.get(ztype, ztype),
                          "allow_transfer": zt})
    return {
        "recursion": (rec["w"][1] if rec and len(rec["w"]) > 1 else "yes"),   # BIND default: yes
        "allow_recursion": _acl(_get(opts, "allow-recursion")),
        "allow_query_cache": _acl(_get(opts, "allow-query-cache")),
        "allow_transfer": _acl(_get(opts, "allow-transfer")),
        "version_hidden": _get(opts, "version") is not None,
        "dnssec_validation": ((_get(opts, "dnssec-validation") or {"w": ["", "auto"]})["w"] + ["auto"])[1],
        "rate_limit": _get(opts, "rate-limit") is not None,
        "zones": zones,
    }


def _is_any(acl) -> bool:
    return bool(acl) and any(x in ("any", "0.0.0.0/0", "::/0") for x in acl)


def check_bind(res, f: dict, is_exposed: bool) -> str:
    """Findings from the BIND configuration. Returns the role."""
    auth = [z for z in f["zones"] if z["type"] in ("primary", "secondary")]
    recursive = f["recursion"] != "no"
    role = " + ".join(r for r, on in (("authoritative", auth), ("resolver", recursive)) if on) or "no zones, no recursion"

    if auth and recursive:
        res.add("medium", "BIND is both authoritative and a recursive resolver",
                "Zone: " + ", ".join(z["name"] for z in auth) + ". An authoritative server should not resolve other names: "
                "a resolver problem (cache poisoning, overload) also affects the published zones. "
                "If recursion is not needed: 'recursion no;'.")
    if recursive and (_is_any(f["allow_recursion"]) or _is_any(f["allow_query_cache"])):
        res.pending("recursion", "high", "BIND: recursion allowed to ANYONE in the configuration (allow-recursion any)",
                    "Open resolver if reachable from the Internet: usable for DDoS amplification attacks.",
                    cause="allow-recursion { any; }")
    if recursive and f["dnssec_validation"] == "no":
        res.add("medium", "BIND: DNSSEC validation disabled (dnssec-validation no)",
                "Forged answers (cache poisoning) are not detected.")
    for z in auth:
        acl = z["allow_transfer"] if z["allow_transfer"] is not None else f["allow_transfer"]
        if z["type"] == "primary" and (acl is None or _is_any(acl)):
            why = "allow-transfer { any; }" if acl else "allow-transfer not set: the BIND default allows it to everyone"
            res.pending(("axfr", z["name"]), "high", f"BIND: zone transfer of '{z['name']}' allowed to anyone",
                        f"{why}. It must be restricted to the secondary servers' addresses.", cause=why)
    if auth and is_exposed and not f["rate_limit"]:
        res.add("low", "Authoritative BIND without rate limiting (rate-limit)",
                "Without a limit on responses per second the server can be used for amplification even "
                "without recursion.")
    return role


# ---------------------------------------------------------------------------- Unbound
def unbound_facts(text: str) -> dict:
    """Unbound configuration (all files concatenated) -> security-relevant settings. Pure function."""
    acl, module, anchor, hide_version = [], None, False, False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        key, _, val = line.partition(":")
        key, val = key.strip(), val.strip().strip('"')
        if key == "access-control":
            parts = val.split()
            if len(parts) >= 2:
                acl.append((parts[0], parts[1]))
        elif key == "module-config":
            module = val
        elif key in ("auto-trust-anchor-file", "trust-anchor-file", "trust-anchor", "trusted-keys-file"):
            anchor = True
        elif key == "hide-version":
            hide_version = val == "yes"
    return {"acl": acl, "validator": module is None or "validator" in module, "anchor": anchor,
            "hide_version": hide_version}


def check_unbound(res, f: dict) -> str:
    open_acl = [n for n, a in f["acl"] if n in ("0.0.0.0/0", "::0/0", "::/0") and a.startswith("allow")]
    if open_acl:
        res.pending("recursion", "high", "Unbound: recursion allowed to ANYONE in the configuration",
                    f"access-control: {', '.join(open_acl)} allow. Open resolver if reachable from the Internet.",
                    cause=f"access-control: {', '.join(open_acl)} allow")
    if not f["validator"] or not f["anchor"]:
        res.add("medium", "Unbound: DNSSEC validation not enabled",
                "module-config without 'validator'" if not f["validator"] else "no trust anchor configured")
    return "resolver"


# ---------------------------------------------------------------------------- dnsmasq
def dnsmasq_facts(text: str, cmdline: str = "") -> dict:
    """dnsmasq options from files and command line (--option=value is equivalent to option=value). Pure function."""
    keys = set()
    for raw in text.splitlines() + [a[2:] for a in shlex.split(cmdline) if a.startswith("--")]:
        line = raw.split("#", 1)[0].strip()
        if line:
            keys.add(line.split("=", 1)[0].strip())
    restricted = bool(keys & {"interface", "listen-address", "local-service", "except-interface"})
    return {"restricted": restricted, "dnssec": "dnssec" in keys}


def check_dnsmasq(res, f: dict, is_exposed: bool) -> str:
    if is_exposed and not f["restricted"]:
        res.pending("recursion", "medium", "dnsmasq answers on all interfaces, without network restrictions",
                    "None of the interface=, listen-address=, local-service options: on a router or a server "
                    "reachable from outside it also answers clients on the Internet.",
                    cause="dnsmasq without interface=/listen-address=/local-service")
    return "forwarder"


# ---------------------------------------------------------------------------- reading on the target
def _cmdline(rem, pid: int) -> str:
    return rem.run(f"tr '\\0' ' ' < /proc/{int(pid)}/cmdline", sudo=True).out.strip()


def _opt(cmdline: str, *names) -> str | None:
    args = shlex.split(cmdline)
    for i, a in enumerate(args):
        for n in names:
            if a == n and i + 1 < len(args):
                return args[i + 1]
            if n.startswith("--") and a.startswith(n + "="):
                return a.split("=", 1)[1]
    return None


def _read_files(rem, patterns) -> str:
    """Contents of several files (wildcards allowed), one after another."""
    q = " ".join(shlex.quote(p).replace("'*'", "*") if "*" not in p else p for p in patterns)
    return rem.run(f"for f in {q}; do [ -f \"$f\" ] && cat \"$f\"; echo; done", sudo=True).out


def _unbound_text(rem, main: str) -> str:
    """unbound.conf plus included files (Ubuntu: include-toplevel: /etc/unbound/unbound.conf.d/*.conf)."""
    text = _read_files(rem, [main])
    inc = re.findall(r'^\s*include(?:-toplevel)?:\s*"?([^"\s]+)"?', text, re.M)
    if inc:
        text += "\n" + _read_files(rem, [i for i in inc if re.fullmatch(r"[\w./*-]+", i)][:10])
    return text


# ---------------------------------------------------------------------------- check
class _Pending:
    """Configuration findings that the external probe can CONFIRM. If the probe confirms them, only the
    external one (the observed fact) is kept, together with the cause found in the configuration, so
    the same issue is not counted twice. If the probe cannot confirm them (server unreachable from the
    controller, firewall), the configuration findings are kept.
    """

    def __init__(self, res):
        self.res, self.items = res, []

    def add(self, *a, **kw):
        self.res.add(*a, **kw)

    def pending(self, key, sev, title, detail, cause=""):
        self.items.append((key, sev, title, detail, cause))

    def cause(self, key) -> str:
        return "; ".join(c for k, *_, c in self.items if k == key and c)

    def flush(self, confirmed):
        for key, sev, title, detail, _ in self.items:
            if key not in confirmed:
                self.res.add(sev, title, detail)


def run(ctx) -> ScanResult:
    res, rem = ScanResult("dns"), ctx.rem
    out = _Pending(res)
    ss_out = rem.run("ss -Htulpn", sudo=True).out
    found = dns_listeners(ss_out)
    orphan = port53_addrs(ss_out) - {a for d in found.values() for a in d["addrs"]}
    if orphan:
        guess = from_ps(rem.run("ps -eo pid=,comm=", sudo=True).out, orphan)
        for n, d in guess.items():
            found.setdefault(n, d)
        if guess:
            res.add("info", "DNS: process identified from the process list, not from the sockets",
                    "`ss` does not show who listens on port 53 even with sudo (typical of containers: root without "
                    "CAP_SYS_PTRACE cannot see other users' processes). The addresses are attributed to: "
                    + ", ".join(guess))
    known = {n: d for n, d in found.items() if n in DAEMONS}
    nmap53 = 53 in {p.get("port") for p in ctx.cache.get("nmap_open", [])}
    if not found:
        if orphan or nmap53:
            # Something answers on port 53 but it is unknown: the external probes still run.
            res.add("info", "DNS: port 53 open but program not identified: controller probes only",
                    ("listening on " + ", ".join(sorted(orphan))) if orphan else "seen by nmap")
            out = _Pending(res)
            out.flush(_external(out, ctx.rem.host, [], False, False))
            return res
        return res.skip("No DNS server listening on port 53")
    if set(known) == {"systemd-resolve"} and not exposed(known["systemd-resolve"]["addrs"]):
        return res.skip("Only the local systemd resolver (127.0.0.53), not reachable from outside")

    any_exposed, restricted_acl, auth_zones, version_hidden = False, True, [], False
    for name, d in found.items():
        label, role = DAEMONS.get(name, (name, "unknown"))
        is_exp = exposed(d["addrs"])
        any_exposed |= is_exp
        cmd = _cmdline(rem, d["pid"])
        if name == "named":
            conf = _opt(cmd, "-c") or ""
            cfg = rem.run(f"named-checkconf -p {shlex.quote(conf)}" if conf else "named-checkconf -p", sudo=True)
            if cfg.rc != 0 or not cfg.out.strip():
                res.add("info", "BIND: configuration cannot be read with named-checkconf", cfg.out[-300:])
                role = "?"
            else:
                f = bind_facts(cfg.out)
                role = check_bind(out, f, is_exp)
                version_hidden |= f["version_hidden"]
                auth_zones += [z["name"] for z in f["zones"] if z["type"] in ("primary", "secondary")]
                restricted_acl &= not _is_any(f["allow_recursion"])
        elif name == "unbound":
            f = unbound_facts(_unbound_text(rem, _opt(cmd, "-c") or "/etc/unbound/unbound.conf"))
            role = check_unbound(out, f)
            version_hidden |= f["hide_version"]
            restricted_acl &= not any(n in ("0.0.0.0/0", "::0/0", "::/0") and a.startswith("allow")
                                      for n, a in f["acl"])
        elif name == "dnsmasq":
            conf = _opt(cmd, "-C", "--conf-file") or "/etc/dnsmasq.conf"
            f = dnsmasq_facts(_read_files(rem, [conf, "/etc/dnsmasq.d/*"]), cmd)
            role = check_dnsmasq(out, f, is_exp)
            restricted_acl &= f["restricted"]
        res.add("info", f"DNS: {label} listening ({'exposed on the network' if is_exp else 'local only'}), role: {role}",
                "Addresses: " + ", ".join(sorted(d["addrs"])))

    confirmed = _external(out, ctx.rem.host, auth_zones, restricted_acl, version_hidden) if any_exposed else set()
    out.flush(confirmed)
    return res


def _external(out, host: str, zones: list, restricted_acl: bool, version_hidden: bool) -> set:
    """Probes from the controller: what the server actually does towards outside clients. Returns the keys
    of the CONFIRMED issues (so the configuration finding is not repeated).
    """
    res, confirmed = out.res, set()
    rec = dnsprobe.probe_recursion(host)
    ver = dnsprobe.probe_version(host)
    res.data["probe"] = {"recursion": rec, "version": ver}
    if rec.get("open"):
        confirmed.add("recursion")
        cause = out.cause("recursion")
        if restricted_acl and not cause:
            res.add("medium", "DNS: recursion granted to the controller (which is among the allowed clients)",
                    f"Answer {rec['rcode']} with 'ra'. The configuration restricts clients: verify that the list does not "
                    "include external networks. From the Internet the server must answer REFUSED.")
        else:
            res.add("high", "DNS: OPEN resolver - answers recursive queries from the controller",
                    f"Answer {rec['rcode']} with 'ra' to a query for {dnsprobe.RECURSION_PROBE}. If the server is "
                    "reachable from the Internet it can be used for DDoS amplification attacks."
                    + (f" Cause in the configuration: {cause}." if cause else ""))
    elif rec.get("answered"):
        res.add("info", f"DNS: recursion refused to the controller ({rec.get('rcode')})",
                "Correct behaviour for a client that is not authorised.")
    elif not rec.get("answered") and ver is not None:
        res.add("info", "DNS: no answer to the recursion probe (the server does answer otherwise)",
                "It may be a forwarder whose upstream server does not answer: in that case it is NOT necessarily closed.")
    if ver and not version_hidden:   # with version "..." in the configuration the text is already fictitious
        res.add("low", f"DNS: software version exposed: {ver}",
                "Anyone can read it with a 'version.bind' query. BIND: version \"...\"; Unbound: hide-version: yes.")
    for z in zones[:MAX_AXFR_ZONES]:
        a = dnsprobe.probe_axfr(host, z)
        if a.get("allowed"):
            confirmed.add(("axfr", z))
            sample = [n.rstrip(".") for n in a["names"] if n.rstrip(".") != z][:8]
            cause = out.cause(("axfr", z))
            # The cause BEFORE the examples: the Markdown detail is cut at 400 characters and the cause
            # (what to fix) is the most useful information.
            res.add("high", f"DNS: zone transfer of '{z}' SUCCEEDED from the controller ({a['records']} records)",
                    (f"Cause in the configuration: {cause}. " if cause else "")
                    + "Anyone in the same position can download the complete list of names. Examples: " + ", ".join(sample))
    return confirmed
