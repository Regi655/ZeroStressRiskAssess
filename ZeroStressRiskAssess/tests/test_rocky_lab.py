"""Real cases from the Rocky Linux 9.8 lab (report of 2026-10-13): checks that do not depend on the distribution.

Every test reproduces a defect seen in that report.
"""
import unittest

from zerostressriskassess.scanners import listeners
from tests.fakes import FakeRemote, make_ctx


class HiddenSocketsTest(unittest.TestCase):
    def test_bind_twenty_cores_one_line(self):  # ISP lab: 40 identical "low" for the named sockets
        ss = "".join(f"{p} UNCONN 0 0 172.28.7.11:53 0.0.0.0:*\n" for p in ["udp"] * 20 + ["tcp"] * 20)
        res = listeners.run(make_ctx(FakeRemote(default_rc=1, rules=[("ss -", ss, 0)])))
        hidden = [f for f in res.findings if "not visible" in f.title]
        self.assertEqual([f.title for f in hidden], ["Listening ports with a process that is not visible: 53/tcp, 53/udp"])
        self.assertIn("CAP_SYS_PTRACE", hidden[0].detail)


class SocketOwnerTest(unittest.TestCase):
    def test_user_and_process_inferred_from_ss_e(self):
        # REAL: BIND as user bind, root without CAP_SYS_PTRACE (capsh): ss -e shows uid:, not the process.
        from tests.fakes import fixture
        rem = FakeRemote(default_rc=1, rules=[("ss -tulpne", fixture("ss_e_no_ptrace.txt"), 0),
                                              ("ps -eo uid=,user=,comm=", fixture("ps_uid_named.txt"), 0)])
        res = listeners.run(make_ctx(rem))
        hidden = [f for f in res.findings if "not visible" in f.title]
        self.assertEqual(len(hidden), 1)
        self.assertIn("user bind (named)", hidden[0].detail)


if __name__ == "__main__":
    unittest.main()
