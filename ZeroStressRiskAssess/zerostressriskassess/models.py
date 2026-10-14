"""Data structures shared by all modules.

Every check returns the same type (ScanResult), so the orchestrator and the report generator
do not depend on the details of nmap, Lynis and the other sources: they only aggregate findings.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")
# Heuristic weight of each severity.
SEV_WEIGHT = {"critical": 10, "high": 5, "medium": 2, "low": 0.5, "info": 0}

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")      # keeps only \t and \n
_BIDI = re.compile(r"[\u202a-\u202e\u2066-\u2069]")        # bidirectional overrides: they change what the reader sees


def clean_text(s, limit: int = 2000) -> str:
    """Sanitise text coming from the target before it is written to the report.

    A compromised target can make commands print control sequences (colours, line erasure,
    bidirectional overrides) to mislead whoever reads the report or the terminal. Target output
    is treated as data, never as trusted content.
    """
    s = _ANSI.sub("", str(s))
    s = _CTRL.sub("", s)
    s = _BIDI.sub("", s)
    return s[:limit]


@dataclass
class Finding:
    severity: str
    title: str
    detail: str = ""


@dataclass
class ScanResult:
    name: str
    status: str = "ok"  # ok | skipped | error
    findings: list = field(default_factory=list)
    data: dict = field(default_factory=dict)
    raw: str = ""
    duration: float = 0.0

    def add(self, severity: str, title: str, detail: str = "") -> None:
        self.findings.append(Finding(severity, clean_text(title, 300), clean_text(detail, 2000)))

    def skip(self, motivo: str) -> "ScanResult":
        self.status = "skipped"
        self.add("info", motivo)
        return self


@dataclass
class Options:
    nmap_ports: str = ""        # "" = top 1000 ports; "-" = all; or a list such as "1-1024,8080"
    clamav_full: bool = False   # False = critical directories only, True = whole filesystem
    clamav_quick: bool = False  # True = only the usual malware locations on servers (no /home)
    keep_tools: bool = False    # True = do NOT uninstall (debugging only)
    skip: set = field(default_factory=set)
    scan_timeout: int = 3600    # maximum seconds per check
    nse: bool = True            # nmap "safe" NSE scripts (ftp-anon, http-git, ssl-cert...)
    nse_tls: bool = False       # also ssl-enum-ciphers ("intrusive" category: dozens of TLS connections)
    lynis_dir: str = ""         # LOCAL Lynis directory: copied to the target and run without installing anything
    local: bool = False         # True = assess the machine itself (no SSH connection)


@dataclass
class Context:
    """Everything a check needs in order to run."""
    rem: object                 # zerostressriskassess.ssh_client.Remote (or Local)
    opts: Options
    osinfo: object = None       # zerostressriskassess.osinfo.OSInfo (filled in after connecting)
    tools_ok: set = field(default_factory=set)  # tools actually available on the target
    cache: dict = field(default_factory=dict)   # data read once and shared between checks


def mark_timeout(res: "ScanResult", r) -> bool:
    """Flag a command interrupted by timeout (rc 124, from `timeout` on the target or from our own limit):
    an interrupted check must not look like a clean one.
    """
    if getattr(r, "rc", None) == 124:
        res.status = "error"
        res.add("medium", f"Check {res.name} interrupted by timeout: PARTIAL result",
                "What was analysed before the interruption is reported; the rest was NOT checked.")
        return True
    return False
