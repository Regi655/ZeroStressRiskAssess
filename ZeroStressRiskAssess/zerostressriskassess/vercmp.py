"""Package version comparison using the same rules as rpm and dpkg.

String comparison is not enough: "1.10" is newer than "1.9" (numbers, not letters), in dpkg
"1.0~rc1" sorts BEFORE "1.0" (tilde means pre-release) and the epoch "1:" overrides everything else.
The comparison decides whether the version fixing a CVE is already available on the target: an
error here turns a fixable vulnerability into "no fix", or vice versa.

Validated against the real tools: `dpkg --compare-versions` and `rpm.vercmp` (rpm 4.18) on real and
generated pairs (tests/test_cve.py).
"""
from __future__ import annotations

import re


# ------------------------------------------------------------------ rpm
def _rpmvercmp(a: str, b: str) -> int:
    """rpm's rpmvercmp algorithm (rpmio/rpmvercmp.c), version 4.x."""
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not a[i].isalnum() and a[i] not in "~^":
            i += 1
        while j < len(b) and not b[j].isalnum() and b[j] not in "~^":
            j += 1
        # tilde sorts before everything, including the end of the string
        if (i < len(a) and a[i] == "~") or (j < len(b) and b[j] == "~"):
            if not (i < len(a) and a[i] == "~"):
                return 1
            if not (j < len(b) and b[j] == "~"):
                return -1
            i += 1
            j += 1
            continue
        # caret sorts after the end of the string but before any other character
        if (i < len(a) and a[i] == "^") or (j < len(b) and b[j] == "^"):
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i += 1
            j += 1
            continue
        if not (i < len(a) and j < len(b)):
            break
        if a[i].isdigit():
            si = i
            while i < len(a) and a[i].isdigit():
                i += 1
            sj = j
            while j < len(b) and b[j].isdigit():
                j += 1
            seg_a, seg_b = a[si:i], b[sj:j]
            if not seg_b:
                return 1          # numeric versus alphabetic: numeric wins
            seg_a, seg_b = seg_a.lstrip("0"), seg_b.lstrip("0")
            if len(seg_a) != len(seg_b):
                return 1 if len(seg_a) > len(seg_b) else -1
        else:
            si = i
            while i < len(a) and a[i].isalpha():
                i += 1
            sj = j
            while j < len(b) and b[j].isalpha():
                j += 1
            seg_a, seg_b = a[si:i], b[sj:j]
            if not seg_b:
                return -1
        if seg_a != seg_b:
            return 1 if seg_a > seg_b else -1
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def _split_evr(evr: str):
    epoch, _, rest = evr.rpartition(":") if ":" in evr else ("0", "", evr)
    version, _, release = rest.partition("-")
    return int(epoch or 0) if epoch.isdigit() else 0, version, release


def rpm_cmp(a: str, b: str) -> int:
    """Compare two rpm EVRs ("1:3.5.8-2.el9_8"): -1, 0, 1. A missing epoch is 0; a missing release sorts
    before any release ("1.0" < "1.0-1"), as rpm.ver does in rpm 4.18.
    """
    ea, va, ra = _split_evr(a)
    eb, vb, rb = _split_evr(b)
    if ea != eb:
        return 1 if ea > eb else -1
    c = _rpmvercmp(va, vb)
    if c:
        return c
    if not ra or not rb:
        return 0 if ra == rb else (-1 if not ra else 1)
    return _rpmvercmp(ra, rb)


# ------------------------------------------------------------------ dpkg
def _order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _dpkg_part(a: str, b: str) -> int:
    """dpkg's verrevcmp (lib/dpkg/version.c)."""
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return 1 if ac > bc else -1
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return 1 if first_diff > 0 else -1
    return 0


def _split_deb(v: str):
    epoch, _, rest = v.partition(":") if re.match(r"^\d+:", v) else ("0", "", v)
    upstream, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return int(epoch), upstream, revision


def deb_cmp(a: str, b: str) -> int:
    ea, ua, ra = _split_deb(a)
    eb, ub, rb = _split_deb(b)
    if ea != eb:
        return 1 if ea > eb else -1
    return _dpkg_part(ua, ub) or _dpkg_part(ra, rb)


def compare(a: str, b: str, kind: str) -> int:
    return deb_cmp(a, b) if kind == "deb" else rpm_cmp(a, b)
