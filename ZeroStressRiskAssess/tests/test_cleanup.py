"""Packaged units with a runtime binary, progress of long commands, compact Lynis output."""
import socket
import time
import unittest

from zerostressriskassess import ssh_client
from zerostressriskassess.scanners import services
from tests.fakes import FakeRemote, make_ctx

LXD_SHOW = ("Id=lxd-agent.service\nFragmentPath=/lib/systemd/system/lxd-agent.service\n"
            "ExecStart={ path=/run/lxd_agent/lxd-agent ; argv[]=/run/lxd_agent/lxd-agent ; }\n")


class ServicesTest(unittest.TestCase):
    def run_srv(self, unit_owned):
        rem = FakeRemote(default_rc=1, rules=[
            ("command -v systemctl", "/usr/bin/systemctl", 0),
            ("list-units", "lxd-agent.service\n", 0),
            ("systemctl show", LXD_SHOW, 0),
            ("dpkg -S /lib/systemd/system/lxd-agent.service", "lxd-agent-loader: ...", 0 if unit_owned else 1),
        ])
        return services.run(make_ctx(rem))

    def test_packaged_unit_runtime_binary_low(self):  # lxd-agent on the VMware VM
        f, = [f for f in self.run_srv(True).findings if "lxd-agent" in f.title]
        self.assertEqual(f.severity, "low")

    def test_unknown_unit_stays_medium(self):
        f, = [f for f in self.run_srv(False).findings if "lxd-agent" in f.title]
        self.assertEqual(f.severity, "medium")


class FakeChan:
    """Fake SSH channel: stays silent for a while (like apt waiting for the lock), then answers."""

    def __init__(self, silent_for):
        self.until = time.time() + silent_for
        self.sent = False

    def set_combine_stderr(self, v): pass
    def settimeout(self, t): pass
    def exec_command(self, c): pass
    def sendall(self, d): pass
    def shutdown_write(self): pass
    def close(self): pass
    def recv_exit_status(self): return 0

    def recv(self, n):
        if time.time() < self.until:
            time.sleep(0.02)
            raise socket.timeout()
        if not self.sent:
            self.sent = True
            return b"done"
        return b""


class ChattyChan(FakeChan):
    """Like Lynis: writes continuously, never silent."""

    def __init__(self, talk_for):
        super().__init__(0)
        self.until = time.time() + talk_for

    def recv(self, n):
        if time.time() < self.until:
            time.sleep(0.02)
            return b"."
        return b""


class ProgressTest(unittest.TestCase):
    def _remote(self, chan):
        rem = ssh_client.Remote("h", "u")
        rem.client = type("C", (), {"get_transport": lambda s: type("T", (), {"open_session": lambda s: chan})()})()
        return rem

    def test_messages_even_if_the_command_writes_continuously(self):  # bug seen on the laptop: Lynis silent for 346 s
        old = ssh_client.HEARTBEAT
        ssh_client.HEARTBEAT = 0.1
        try:
            rem = self._remote(ChattyChan(talk_for=0.35))
            notes = []
            rem.progress = notes.append
            rem.run("lynis audit system", timeout=10)
        finally:
            ssh_client.HEARTBEAT = old
        self.assertGreaterEqual(len(notes), 2)

    def test_total_timeout_even_if_the_command_writes(self):
        rem = self._remote(ChattyChan(talk_for=5))
        t = time.time()
        r = rem.run("endless command", timeout=0.3)
        self.assertLess(time.time() - t, 2)
        self.assertEqual(r.rc, 124)

    def test_messages_during_long_wait(self):
        old = ssh_client.HEARTBEAT
        ssh_client.HEARTBEAT = 0.1
        try:
            rem = ssh_client.Remote("h", "u")
            chan = FakeChan(silent_for=0.35)
            rem.client = type("C", (), {"get_transport": lambda s: type("T", (), {"open_session": lambda s: chan})()})()
            notes = []
            rem.progress = notes.append
            r = rem.run("\n# comment\napt-get install -y clamav\n", timeout=10)
        finally:
            ssh_client.HEARTBEAT = old
        self.assertEqual(r.out, "done")
        self.assertGreaterEqual(len(notes), 2)
        self.assertIn("apt-get install -y clamav", notes[0])  # the first real line, not the comment


if __name__ == "__main__":
    unittest.main()
