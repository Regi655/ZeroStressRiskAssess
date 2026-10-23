"""Stable fingerprints of the problems: recognising "the same problem" in two runs.

WHY: the report IDs (R01, F001...) are positional: one problem more and they all shift. To compare two runs on
the same target ("what was fixed, what is new, what is left") an identity is needed that depends on the PROBLEM,
not on its position.

The fingerprint is built from the checks that saw the problem + its title, NORMALISED. Normalisation removes what
changes while the problem stays the same, and keeps what identifies the object:
  - "41 security updates..." / "42 security updates..."  -> same problem (count)
  - "Lynis hardening suggestions (14)", "(6 records)"    -> counts in brackets removed
  - "CPU 93.8%", "Hardening index 62/100"                -> measurements normalised
  - versions ("vsftpd 3.0.5", "BIND 9.18.39")            -> normalised: updating the software does not make
                                                            "version exposed" a NEW problem
  - ports, accounts, paths ("port 21", "'dev2'", "/opt/app") -> KEPT: they are the object.
keys() returns two keys: the full one, and a looser one (title only, without anything in brackets) used as a
fallback when the checks or a bracketed list changed but the problem is the same.
"""
from __future__ import annotations

import hashlib
import re

_STEPS = [
    (re.compile(r"\s*\((?:\+?\d+ [^)]*|[^)]*\d+ (?:records?|entries|similar|files?|lines?)[^)]*)\)"), ""),
    (re.compile(r"\b\d+(?:\.\d+)?\s*%"), "#%"),            # percentages
    (re.compile(r"\b\d+/100\b"), "#/100"),                 # indices
    (re.compile(r"\S*\d+\.\d+\S*"), "#v"),                 # words with "digit.digit": versions, IP addresses
    (re.compile(r"\s*\(\d+\)"), ""),                       # count in brackets: "(14)"
    (re.compile(r"^\d+ "), "# "),                          # leading count: "42 security updates"
    (re.compile(r"\s+"), " "),
]
_BRACKETS = re.compile(r"\s*\([^)]*\)?")


def normalize(text: str) -> str:
    t = (text or "").strip()
    for rx, rep in _STEPS:
        t = rx.sub(rep, t)
    return t.strip()


def keys(scans, title: str):
    """(full key, loose key) of a problem of the risk table (or of a finding: scans = its check name)."""
    scans = [scans] if isinstance(scans, str) else sorted(scans or [])
    t = normalize(title)
    return f"{','.join(scans)}|{t}", _BRACKETS.sub("", t).strip()


def fingerprint(scans, title: str) -> str:
    """12 hexadecimal characters, stable across runs."""
    return hashlib.sha256(keys(scans, title)[0].encode("utf-8")).hexdigest()[:12]
