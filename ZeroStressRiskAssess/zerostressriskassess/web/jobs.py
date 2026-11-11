"""Assessments started from the web interface: one detached process per run, state kept in files.

WHY a separate process and not a thread of the Streamlit server: an assessment lasts more than an hour. Streamlit
reruns the page script on every click and the server may be restarted; a process in its own session, writing to
files, survives both, and the page only reads those files. Stopping it sends SIGINT, exactly like Ctrl-C in a
terminal, so the cleanup on the target (removal of the installed tools) runs as usual.

Each run has a directory OUT_DIR/.jobs/<id>/ (mode 700):
    job.json   what was asked (command line WITHOUT secrets), pid, start time
    log.txt    everything the run prints (the same lines as in a terminal)
    rc         exit code, written by runner.py when the run ends
    report     path of the report directory, when an assessment completed

Secrets (SSH password, key passphrase, sudo password) are written to the process's stdin and read once by
runner.py: never on the command line (visible to every user through `ps`) nor in the environment (inherited by
nmap and the other programs the run starts).
"""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

JOBS = ".jobs"


@dataclass
class Job:
    id: str
    dir: Path
    info: dict

    @property
    def log(self) -> str:
        try:
            return (self.dir / "log.txt").read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    @property
    def rc(self):
        try:
            return int((self.dir / "rc").read_text().strip())
        except (OSError, ValueError):
            return None

    @property
    def report_dir(self):
        try:
            p = Path((self.dir / "report").read_text(encoding="utf-8").strip())
            return p if p.is_dir() else None
        except OSError:
            return None

    @property
    def running(self) -> bool:
        return self.rc is None and _alive(self.info.get("pid"))

    @property
    def status(self) -> str:
        rc = self.rc
        if rc is None:
            return "running" if _alive(self.info.get("pid")) else "lost"   # killed without writing rc
        return {0: "completed", 130: "interrupted"}.get(rc, f"failed (rc={rc})")

    @property
    def waiting_confirmation(self) -> bool:
        """Recovery preview that stopped at "Remove these N packages from the target?": offer the confirmation."""
        return self.info.get("kind") == "recover-preview" and self.rc is not None and "Remove these" in self.log

    def stop(self) -> bool:
        """Ctrl-C to the whole process group (zsra and the nmap/ssh-audit it started): the cleanup still runs."""
        pid = self.info.get("pid")
        if not self.running:
            return False
        try:
            os.killpg(pid, signal.SIGINT)
        except (ProcessLookupError, PermissionError):
            return False
        return True


def _alive(pid) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # A finished child that nobody waited for is a zombie: reap it, it is not running any more.
    try:
        done, _ = os.waitpid(pid, os.WNOHANG)
        return done == 0
    except ChildProcessError:   # not our child (e.g. started before a server restart): kill(0) is the answer
        return True


def build_argv(mode: str, host: str, user: str = "", port: int = 22, key: str = "", opts: dict | None = None):
    """zsra command line for a form submission. mode: "scan", "recon", "recover". Secrets are NOT included."""
    o = opts or {}
    argv = [host.strip()]
    if mode == "recon":
        argv.append("--recon-only")
    else:
        if user.strip():
            argv += ["-u", user.strip()]
        if key.strip():
            argv += ["-i", key.strip()]
    if port and int(port) != 22:
        argv += ["-p", str(int(port))]
    if o.get("accept_new_hostkey") and mode != "recon":
        argv.append("--accept-new-hostkey")
    if mode == "recover":
        return argv + ["--recover"]
    if o.get("nmap_ports", "").strip():
        argv += ["--nmap-ports", o["nmap_ports"].strip()]
    nse = o.get("nse", "default")
    if nse == "off":
        argv.append("--no-nse")
    elif nse == "tls":
        argv.append("--nse-tls")
    zones = (o.get("dns_zones") or "").split()
    if zones:
        argv += ["--dns-zone", *zones]
    if mode == "scan":
        clam = o.get("clamav", "default")
        if clam in ("quick", "full"):
            argv.append(f"--clamav-{clam}")
        if o.get("no_install"):
            argv.append("--no-install")
        if o.get("keep_tools"):
            argv.append("--keep-tools")
    if o.get("skip"):
        argv += ["--skip", *o["skip"]]
    if o.get("scan_timeout") and int(o["scan_timeout"]) != 60:
        argv += ["--scan-timeout", str(int(o["scan_timeout"]))]
    if o.get("upload") is True:      # None = the portal configuration decides (zsra-portal login --auto)
        argv.append("--upload")
    elif o.get("upload") is False:
        argv.append("--no-upload")
    return argv


def start(out_dir, argv, secrets=None, kind="scan", confirm=True) -> Job:
    """Start a run. confirm=True adds --yes (the page already asked for the authorisation); confirm=False answers
    "no" to the question instead (recovery preview: it lists what it would remove, then stops)."""
    out_dir = Path(out_dir).resolve()
    root = out_dir / JOBS
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = re.sub(r"[^A-Za-z0-9.-]", "_", argv[0] if argv else "local")[:60]
    jid = f"{time.strftime('%Y%m%d-%H%M%S')}_{target}_{kind}"
    d = root / jid
    d.mkdir(mode=0o700)
    full = argv + ["--out-dir", str(out_dir), "--no-banner"] + (["--yes"] if confirm else [])
    log = os.open(d / "log.txt", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        # Argument list, no shell: nothing typed in the form is ever interpreted as a command.
        # The run starts in another directory: the package is found through PYTHONPATH even when it is used from a
        # checkout without being installed with pip.
        pkg_root = str(Path(__file__).resolve().parents[2])
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in (pkg_root, os.environ.get("PYTHONPATH")) if p))
        proc = subprocess.Popen([sys.executable, "-u", "-m", "zerostressriskassess.web.runner", str(d), *full],
                                stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True, cwd=str(out_dir.parent), env=env)
    finally:
        os.close(log)
    payload = json.dumps({k: v for k, v in (secrets or {}).items() if v}) + "\n" + ("" if confirm else "no\n")
    try:
        proc.stdin.write(payload.encode("utf-8"))
        proc.stdin.close()
    except BrokenPipeError:
        pass
    info = {"id": jid, "kind": kind, "argv": full, "pid": proc.pid, "started": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target": argv[0] if argv else "local"}
    _write_private(d / "job.json", json.dumps(info, indent=2))
    return Job(jid, d, info)


def list_jobs(out_dir) -> list:
    root = Path(out_dir) / JOBS
    jobs = []
    for d in sorted(root.glob("*/"), reverse=True) if root.is_dir() else []:
        try:
            info = json.loads((d / "job.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        jobs.append(Job(d.name, d, info))
    return jobs


def _write_private(path: Path, text: str):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
