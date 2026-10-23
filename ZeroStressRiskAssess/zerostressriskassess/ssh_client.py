"""Minimal paramiko wrapper: runs commands and uploads files.

The rest of the project only calls `rem.run(...)`: replacing paramiko, or testing against a fake
target, only requires changes here.
"""
from __future__ import annotations

import shlex
import socket
import time
from dataclasses import dataclass

import paramiko


TRUSTED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


HEARTBEAT = 30  # seconds between two progress messages


def _short(cmd: str) -> str:
    """First meaningful line of the command, shortened, for progress messages."""
    for line in cmd.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            return line[:70] + ("…" if len(line) > 70 else "")
    return "?"


@dataclass
class CmdResult:
    cmd: str
    rc: int
    out: str  # stdout + stderr combined: the text matters, not the channel


class Remote:
    def __init__(self, host, user, port=22, key_file=None, password=None,
                 sudo_password=None, accept_new_hostkey=False, passphrase=None):
        self.host, self.user, self.port = host, user, port
        self.key_file, self.password = key_file, password
        self.sudo_password = sudo_password
        self.passphrase = passphrase
        self.auth_method = None   # "publickey" / "password" / ...: reported in the metadata
        self.accept_new_hostkey = accept_new_hostkey
        self.client = None
        # Called every HEARTBEAT seconds during long commands (set by the orchestrator).
        # Without it the tool appears frozen for minutes during apt or ClamAV.
        self.progress = None

    # ------------------------------------------------------------------ connection
    def connect(self):
        c = paramiko.SSHClient()
        c.load_system_host_keys()
        # RejectPolicy: accepting any host key would let a man-in-the-middle impersonate the target.
        # --accept-new-hostkey makes acceptance an explicit decision on first contact.
        c.set_missing_host_key_policy(
            paramiko.AutoAddPolicy() if self.accept_new_hostkey else paramiko.RejectPolicy())
        c.connect(self.host, port=self.port, username=self.user,
                  key_filename=self.key_file, password=self.password, passphrase=self.passphrase,
                  timeout=15, allow_agent=True, look_for_keys=True)
        # Keepalive: ClamAV and Lynis run for minutes; without keepalive packets, firewalls and NAT
        # devices may drop the idle session.
        c.get_transport().set_keepalive(30)
        self.client = c
        # Which method actually authenticated (key or password; not obvious with --ask-pass)
        handler = getattr(c.get_transport(), "auth_handler", None)
        self.auth_method = getattr(handler, "auth_method", None)

    def close(self):
        if self.client:
            self.client.close()
            self.client = None

    # ------------------------------------------------------------------ execution
    @staticmethod
    def _wrap(cmd: str, need_sudo: bool, has_sudo_pw: bool, trusted_path: bool = True) -> str:
        """Build the remote command line.

        LC_ALL=C: programs (apt, dpkg, tune2fs...) translate their messages into the system language,
        while the parsers look for English keywords ("Candidate:", "Filesystem state"). On a localised
        target ("Candidato:") they would fail and the tool would conclude that packages do not exist.
        The neutral "C" locale makes the output identical everywhere. The export is placed INSIDE
        bash -c so that it also applies after sudo, which resets the environment.

        Trusted PATH: by default commands run with /usr/sbin:/usr/bin:/sbin:/bin, WITHOUT
        /usr/local/bin and similar directories. Otherwise an attacker placing a fake `ps` in
        /usr/local/bin would have it executed by us, as root, instead of the real one.
        Only the check that looks for shadowed commands uses trusted_path=False.
        """
        inner = "export LC_ALL=C LANG=C LANGUAGE=C; "
        if trusted_path:
            inner += "export PATH=" + TRUSTED_PATH + "; "
        inner += cmd
        wrapped = f"bash -c {shlex.quote(inner)}"
        if need_sudo:
            wrapped = ("sudo -S -p '' " if has_sudo_pw else "sudo -n ") + wrapped
        return wrapped

    def run(self, cmd: str, sudo: bool = False, timeout: int = 600, trusted_path: bool = True) -> CmdResult:
        """Run `cmd` with bash; with sudo=True it runs as root.

        The sudo password is sent on stdin (never on the command line, where every user of the
        target could see it with `ps`).
        """
        need_sudo = sudo and self.user != "root"
        wrapped = self._wrap(cmd, need_sudo, bool(self.sudo_password), trusted_path)

        chan = self.client.get_transport().open_session()
        chan.set_combine_stderr(True)
        chan.settimeout(5)
        chan.exec_command(wrapped)
        if need_sudo and self.sudo_password:
            chan.sendall((self.sudo_password + "\n").encode())
        # End of input: with a WRONG sudo password, sudo prints "Sorry, try again." and waits for another attempt.
        # Without EOF it waited until the timeout (600 s for each command; lab clean and secure, 2026-10-23); with
        # EOF it gives up at once. No command of the tool reads stdin, so closing it changes nothing else.
        chan.shutdown_write()

        start = time.time()
        buf, deadline, next_note = [], start + timeout, start + HEARTBEAT
        while True:
            try:
                data = chan.recv(65536)
            except socket.timeout:
                data = None  # no data within 5 seconds: not finished yet, keep waiting
            # Progress and timeout are checked on EVERY iteration, not only when the command is silent:
            # otherwise a command that prints continuously (e.g. Lynis) would never trigger them.
            now = time.time()
            if self.progress and now >= next_note:
                self.progress(f"... still running after {int(now - start)}s: {_short(cmd)}")
                next_note = now + HEARTBEAT
            if now > deadline:   # TOTAL timeout
                chan.close()
                return CmdResult(cmd, 124, b"".join(buf).decode("utf-8", "replace") + "\n[TIMEOUT]")
            if data is None:
                continue
            if not data:
                break
            buf.append(data)
        rc = chan.recv_exit_status()
        return CmdResult(cmd, rc, b"".join(buf).decode("utf-8", "replace").strip())

    # ------------------------------------------------------------------ files
    def home(self) -> str:
        sftp = self.client.open_sftp()
        try:
            return sftp.normalize(".")
        finally:
            sftp.close()

    def upload_bytes(self, remote_path: str, data: bytes) -> None:
        sftp = self.client.open_sftp()
        try:
            with sftp.open(remote_path, "wb") as f:
                f.write(data)
            sftp.chmod(remote_path, 0o600)
        finally:
            sftp.close()

    def upload_text(self, remote_path: str, content: str) -> None:
        sftp = self.client.open_sftp()
        try:
            with sftp.open(remote_path, "wb") as f:
                f.write(content.encode("utf-8"))
        finally:
            sftp.close()


class NoLogin:
    """Target of a --recon-only assessment: only its address is known, and NO command can run on it.

    The external checks only use host and port. If a check tried to run a command on the target anyway, it
    must fail loudly rather than silently touch a machine that must not be contaminated.
    """
    progress = None

    def __init__(self, host, port=22):
        self.host, self.port = host, port
        self.calls = []

    def run(self, cmd, **kw):
        raise RuntimeError("recon-only: no command may be run on the target")

    def connect(self):
        raise RuntimeError("recon-only: no login on the target")

    def close(self):
        pass


class Local:
    """Same interface as Remote, but commands run ON THE MACHINE BEING ASSESSED (--local).

    The assessment can also run from inside (e.g. a server with no other machine to connect from).
    Checks only call `run()` and do not know whether SSH or the local shell is used. As root,
    commands run directly; as a regular user they go through sudo (password on stdin, never on the
    command line, as for Remote).
    """

    def __init__(self, sudo_password=None):
        import getpass
        import os
        import socket as _s
        self.host = _s.gethostname() or "localhost"
        self.user = "root" if os.geteuid() == 0 else getpass.getuser()
        self.port = None
        self.sudo_password = sudo_password
        self.auth_method = "local (no SSH connection)"
        self.progress = None

    def connect(self):
        pass

    def close(self):
        pass

    def run(self, cmd: str, sudo: bool = False, timeout: int = 600, trusted_path: bool = True) -> CmdResult:
        import subprocess
        need_sudo = sudo and self.user != "root"
        wrapped = Remote._wrap(cmd, need_sudo, bool(self.sudo_password), trusted_path)
        p = subprocess.Popen(["bash", "-c", wrapped], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        if need_sudo and self.sudo_password:
            p.stdin.write((self.sudo_password + "\n").encode())
        p.stdin.close()
        start, buf = time.time(), []
        next_note = start + HEARTBEAT
        import selectors
        sel = selectors.DefaultSelector()
        sel.register(p.stdout, selectors.EVENT_READ)
        while True:
            now = time.time()
            if self.progress and now >= next_note:
                self.progress(f"... still running after {int(now - start)}s: {_short(cmd)}")
                next_note = now + HEARTBEAT
            if now - start > timeout:
                p.kill()
                p.wait()
                p.stdout.close()
                sel.close()
                return CmdResult(cmd, 124, b"".join(buf).decode("utf-8", "replace") + "\n[TIMEOUT]")
            if sel.select(timeout=min(5.0, max(0.1, start + timeout - now))):
                data = p.stdout.read1(65536)
                if not data:
                    break
                buf.append(data)
        rc = p.wait()
        p.stdout.close()
        sel.close()
        return CmdResult(cmd, rc, b"".join(buf).decode("utf-8", "replace").strip())

    def home(self) -> str:
        import os
        return os.path.expanduser("~")

    def upload_bytes(self, remote_path: str, data: bytes) -> None:
        import os
        fd = os.open(remote_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)

    def upload_text(self, remote_path: str, content: str) -> None:
        self.upload_bytes(remote_path, content.encode("utf-8"))
