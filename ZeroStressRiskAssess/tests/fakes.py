"""A fake target for the tests: it answers commands with prepared output, without SSH.

Every check talks to the target only through `ctx.rem.run(cmd)`. Passing this object instead of a real
Remote lets the checks run against REAL output recorded on virtual machines and labs (fixtures/) in about
a second, without any machine running, after every change.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from zerostressriskassess.models import Context, Options
from zerostressriskassess.osinfo import OSInfo
from zerostressriskassess.ssh_client import CmdResult

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


@dataclass
class Result:
    out: str
    rc: int = 0


@dataclass
class FakeRemote:
    """rules: list of (pattern, output, rc). The FIRST rule whose pattern appears in the command (plain
    string) or matches it (compiled regex) wins. No matching rule: empty output and default_rc."""
    rules: list = field(default_factory=list)
    default_rc: int = 0
    host: str = "10.0.0.1"
    user: str = "admin"
    port: int = 22
    calls: list = field(default_factory=list)

    def run(self, cmd, sudo=False, timeout=600, trusted_path=True, **kw):
        self.calls.append(cmd)
        for pat, out, *rc in self.rules:
            hit = pat.search(cmd) if isinstance(pat, re.Pattern) else pat in cmd
            if hit:
                return Result(out, rc[0] if rc else 0)
        return Result("", self.default_rc)

    progress: object = None

    def connect(self):
        pass

    def close(self):
        pass

    def home(self):
        return "/home/admin"

    def upload_text(self, path, content):
        pass

    def upload_bytes(self, path, data):
        pass


class LocalRemote:
    """Runs the commands FOR REAL, locally, with bash (sudo is ignored: the tests that use it run as root).
    Used to exercise the tool's shell scripts on a real system, not only against canned answers."""
    host = "127.0.0.1"
    port = 22

    def __init__(self, home):
        self._home = str(home)
        self.calls = []

    def run(self, cmd, sudo=False, timeout=600, **kw):
        import subprocess
        self.calls.append(cmd)
        p = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, timeout=timeout)
        return CmdResult(cmd, p.returncode, (p.stdout + p.stderr).strip())

    def home(self):
        return self._home

    def upload_bytes(self, path, data):
        Path(path).write_bytes(data)
        Path(path).chmod(0o600)


def make_ctx(rem, skip=(), tools_ok=()):
    opts = Options(skip=set(skip), scan_timeout=60)
    ctx = Context(rem=rem, opts=opts)
    ctx.osinfo = OSInfo(id="ubuntu", version_id="22.04", pretty="Ubuntu 22.04.5 LTS", pkg_mgr="apt",
                        kernel="5.15.0-198-generic", arch="x86_64")
    ctx.tools_ok = set(tools_ok)
    return ctx
