"""Hardening audit with Lynis.

Lynis checks hundreds of settings (SSH, kernel, permissions, password policy...) and produces a
0-100 "hardening index". It does not look for malware: it measures how securely the system is
configured.
"""
from __future__ import annotations

from .. import portable
from ..models import ScanResult

MAX_SUGGESTIONS = 40  # Lynis often produces dozens: keeps the report readable

# Lynis tests covered by a dedicated check of ours: when that check is active, the Lynis warning stays
# in the report as "info" (otherwise the same issue would be counted twice).
# Suggestions duplicating checks performed more precisely by our own modules are not repeated one by
# one; only their number is reported. If our check is skipped with --skip, they become visible again.
SUGG_COVERED = {"SSH-7408": "sshd", "PKGS-7392": "updates", "PKGS-7420": "updates", "FIRE-4590": "firewall",
                "HOME-9304": "permissions", "HOME-9306": "permissions",
                "KRNL-6000": "hardening", "AUTH-9328": "hardening", "ACCT-9628": "hardening"}
# Lynis tests that, inside a CONTAINER, concern the host or are meaningless (no own kernel, boot
# process, syslog or drivers). Without this filter a containerised target would receive host-level
# warnings (e.g. "klogd is not running" as HIGH) and advice about partitions, USB/firewire drivers,
# kernel protocols, core dumps and boot services.
HOST_ONLY = ("BOOT-", "KRNL-", "USB-", "STRG-", "FILE-6310", "NETW-3200", "LOGG-", "ACCT-", "TIME-")
# Warnings about Lynis itself, not the target ("this release is more than 4 months old").
SUGG_DROP = {"LYNIS"}

COVERED = {"AUTH-9204": "accounts", "AUTH-9208": "accounts", "AUTH-9283": "accounts",
           "FIRE-4512": "firewall", "PKGS-7392": "updates"}


def _split(val: str):
    p = (val.split("|") + ["", "", "", ""])[:4]
    return tuple(x.strip() for x in p)


def _fields(val: str):
    """From 'ID|description|detail|solution' derive (title, detail). The detail (e.g. which SSH directive
    to change) is what distinguishes ten identical lines from ten distinct actions.
    """
    p = (val.split("|") + ["", "", "", ""])[:4]
    ident, desc, extra, fix = (x.strip() for x in p)
    skip = ("", "-", "none")
    title = desc or val
    if extra not in skip:
        title += f" [{extra}]"
    return title, ident + (f" - solution: {fix}" if fix not in skip else "")


def run(ctx) -> ScanResult:
    res, rem = ScanResult("lynis"), ctx.rem
    if getattr(ctx.opts, "lynis_dir", "") and portable.available(ctx.opts.lynis_dir):
        rc, out, rep = portable.run_lynis(rem, ctx.opts.lynis_dir, ctx.opts.scan_timeout)
        res.raw = out
        res.data["mode"] = "portable (copied from the controller, no package installed)"
        res.data["target_logs"] = "none: temporary directory deleted"
        if not rep:
            res.status = "error"
            res.add("info", "Portable Lynis: no report produced", out[-500:])
            return res
        return parse(res, rep, ctx)
    return res.skip("Lynis not found on the controller: download it with "
                    "'git clone https://github.com/CISOfy/lynis vendor/lynis' (see README)")


def parse(res, rep: str, ctx) -> ScanResult:
    """Lynis report.dat -> findings (same format for packaged and portable Lynis)."""
    in_container = bool(ctx.cache.get("container"))
    host_only = []
    suggestions = 0
    groups: dict = {}  # Lynis ID -> [(description, detail)]: suggestions with the same ID are merged
    covered: dict = {}  # Lynis ID -> our check that already covers it
    for line in rep.splitlines():
        key, _, val = line.partition("=")
        if key == "hardening_index" and val.isdigit():
            idx = int(val)
            res.data["hardening_index"] = idx
            # Informational only: the percentage of Lynis tests passed, i.e. a summary of the suggestions listed
            # below. Counting it as "medium" as well would weigh them twice.
            res.add("info", f"Lynis hardening index: {idx}/100",
                    "Share of Lynis tests passed: a configuration indicator, not a risk measure.")
        elif key == "lynis_version":
            res.data["lynis_version"] = val
        elif key == "warning[]":
            ident, desc, extra, fix = _split(val)  # format: ID|description|detail|solution
            title, det = _fields(val)
            own = COVERED.get(ident)
            if in_container and ident.startswith(HOST_ONLY):
                host_only.append(ident)
            elif own and own not in ctx.opts.skip:
                res.add("info", title + f" (already covered by the '{own}' check)", det)
            else:
                res.add("high", title, det)
        elif key == "suggestion[]":
            suggestions += 1
            ident, desc, extra, fix = _split(val)
            own = SUGG_COVERED.get(ident)
            if ident in SUGG_DROP:
                continue
            if in_container and ident.startswith(HOST_ONLY):
                host_only.append(ident)
                continue
            if own and own not in ctx.opts.skip:
                covered.setdefault(ident, own)
                continue
            groups.setdefault(ident, []).append((desc, extra))
    for n, (ident, items) in enumerate(groups.items()):
        if n >= MAX_SUGGESTIONS:
            break
        if len(items) == 1:
            title, det = _fields(f"{ident}|{items[0][0]}|{items[0][1]}|")
            res.add("low", title, det)
        else:
            # E.g. ten "Consider hardening SSH configuration [...]" lines: a single line with the list.
            first = items[0][0] or ident
            parts = [e if e not in ("", "-", "none") else d for d, e in items]
            same = any(e not in ("", "-", "none") for _, e in items)  # same directive, different parameters
            title = f"{first} ({len(items)} items)" if same else f"{first} (+{len(items) - 1} similar)"
            res.add("low", title, f"{ident}: " + "; ".join(parts))
    if host_only:
        res.add("info", f"{len(host_only)} Lynis tests not applicable in a container (they concern the host)",
                "Kernel, boot, syslog, partitions, drivers: in a container they belong to the host. "
                + ", ".join(dict.fromkeys(host_only)))
    if covered:
        res.add("info", f"{len(covered)} Lynis suggestions not repeated: already covered by our own checks",
                ", ".join(f"{i} ({s})" for i, s in covered.items()))
    res.data["suggestions_total"] = suggestions
    return res
