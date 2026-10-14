"""Automatic masking of secrets in the report.

The external tools copy fragments of configuration files into their output (Lynis, and the details
produced by the checks themselves). These fragments may contain passwords, tokens, private keys or
password hashes. A security report that spreads the client's credentials would itself be a security
incident, so masking ALWAYS runs before anything is written.

The VALUE is replaced, not the line: "password=hunter2" becomes "password=[MASKED]", so the reader
knows a secret was there (useful in itself: a clear-text password in that file) without seeing it.

Known limitation: these are regular expressions, not semantic analysis. They cover common formats;
a secret in an unusual format may slip through, so reports should still be reviewed before sharing.
"""
from __future__ import annotations

import re

MASK = "[MASKED]"

# (name, regex, group to mask). Order matters: larger blocks first.
PATTERNS = [
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), 0),
    ("password hash", re.compile(r"\$(?:1|2[aby]|5|6|y|gy|7)\$[^\s:$]*\$[./A-Za-z0-9$]{8,}"), 0),
    ("AWS key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), 0),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), 0),
    ("API key", re.compile(r"\b(?:sk|pk|rk)[-_](?:live|test|proj|ant)?[-_]?[A-Za-z0-9_-]{20,}\b"), 0),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 0),
    ("credentials in URL", re.compile(r"(?<=://)[^/\s:@]+:([^@\s/]+)(?=@)"), 1),
    ("Authorization", re.compile(r"(?i)\bauthorization\s*:\s*(?:basic|bearer)\s+([A-Za-z0-9+/=._-]{8,})"), 1),
    # Passwords on the command line: "mysql -u root -pSECRET" (attached to -p, no space; uppercase
    # "-P 3306" is the port) and "sshpass -p SECRET". Common in .bash_history and cron.
    ("command-line password", re.compile(
        r"\b(?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b[^\n]*?\s-p([^\s'\"]\S*)"), 1),
    ("command-line password", re.compile(r"\bsshpass\b[^\n]*?\s-p\s*(\S+)"), 1),
    # key = value, key: value, "password": "x", define('DB_PASSWORD', 'x').
    # False-positive guards, both derived from real reports:
    #  - the keyword must not be part of a longer name or a path:
    #    "NOPASSWD:" (sudoers), "/etc/passwd: permissions too wide";
    #  - a comma separates name and value ONLY between quotes (PHP syntax): in "/etc/passwd, /etc/shadow"
    #    the comma separates two list items, and /etc/shadow would otherwise be masked.
    ("assignment", re.compile(
        r"""(?ix)
        (?<![a-z0-9/.-])
        (?:pass(?:word|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|
           client[_-]?secret|auth[_-]?key|db_password|smtp_pass)
        (?:["']?\s*(?:=>|=|:)\s*["']?|["']\s*,\s*["'])
        ([^\s"',;)]{3,})
        """), 1),
    # "passwd" is also a file and a command name: only the passwd=value form is matched.
    ("assignment", re.compile(r"(?i)(?<![a-z0-9/.-])passwd\s*=\s*[\"']?([^\s\"',;)]{3,})"), 1),
]


def mask(text: str):
    """(masked text, counts per type). Pure function."""
    if not text:
        return text, {}
    counts = {}

    for name, rx, group in PATTERNS:
        def repl(m, name=name, group=group):
            value = m.group(group)
            if not value or value == MASK or value.lower() in ("none", "null", "false", "true", "yes", "no", "*", "x"):
                return m.group(0)
            counts[name] = counts.get(name, 0) + 1
            if group == 0:
                return MASK
            s, e = m.span(group)
            base = m.start(0)
            whole = m.group(0)
            return whole[:s - base] + MASK + whole[e - base:]
        text = rx.sub(repl, text)
    return text, counts


def mask_report(rep: dict) -> dict:
    """Mask titles, details and raw output of every check. Modifies rep in place and returns the counts."""
    total = {}

    def add(c):
        for k, v in c.items():
            total[k] = total.get(k, 0) + v

    for sc in rep.get("scans", []):
        for f in sc.get("findings", []):
            for key in ("title", "detail"):
                f[key], c = mask(f.get(key, ""))
                add(c)
        sc["raw"], c = mask(sc.get("raw", ""))
        add(c)
    rep.setdefault("meta", {})["masked_secrets"] = total
    return total
