"""Baseline hardening (hardening check).

hardening_sandbox_vm.txt is the REAL output of the script in the development sandbox VM (Ubuntu 24.04
without systemd: the /usr/lib/sysctl.d files are not applied, which is why protected_symlinks is 0).
The other cases are SYNTHETIC, in the script's format: stock values of a normally installed Ubuntu 24.04
(according to the sysctl.d files of the procps/systemd packages), a Docker host, a container.
"""
import unittest

from zerostressriskassess.scanners import hardening
from tests.fakes import FakeRemote, fixture, make_ctx

UBUNTU_STOCK = """CONTAINER|0
SYS|kernel.randomize_va_space|2
SYS|fs.protected_symlinks|1
SYS|fs.protected_hardlinks|1
SYS|net.ipv4.conf.all.accept_source_route|0
SYS|fs.protected_fifos|1
SYS|fs.protected_regular|2
SYS|fs.suid_dumpable|2
SYS|kernel.kptr_restrict|1
SYS|kernel.dmesg_restrict|1
SYS|kernel.yama.ptrace_scope|1
SYS|kernel.unprivileged_bpf_disabled|2
SYS|net.ipv4.conf.all.accept_redirects|1
SYS|net.ipv4.conf.all.send_redirects|1
SYS|net.ipv4.tcp_syncookies|1
SYS|net.ipv4.conf.all.rp_filter|2
SYS|net.ipv4.ip_forward|0
MNT|/tmp|/|rw,relatime
MNT|/dev/shm|/dev/shm|rw,nosuid,nodev,inode64
MNT|/var/tmp|/|rw,relatime
LOGIN|UMASK 022
LOGIN|ENCRYPT_METHOD YESCRYPT
PROC|systemd-timesyncd
LINK|2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT
"""


def ev(text):
    return [(s, t) for s, t, _ in hardening.evaluate(hardening.parse(text))]


class HardeningTest(unittest.TestCase):
    def test_sandbox_vm(self):
        got = ev(fixture("hardening_sandbox_vm.txt"))
        self.assertEqual([t for s, t in got if s == "medium"], ["Kernel: fs.protected_symlinks = 0 (expected 1)"])
        self.assertIn(("low", "Kernel parameters to harden (6)"), got)
        self.assertIn(("low", "/dev/shm mounted without nodev, nosuid, noexec"), got)

    def test_stock_ubuntu_no_medium(self):
        got = ev(UBUNTU_STOCK)
        self.assertFalse([t for s, t in got if s in ("medium", "high", "critical")], got)
        self.assertIn(("low", "Kernel parameters to harden (2)"), got)   # the two redirect settings, as in CIS

    def test_container_kernel_info_only(self):
        got = ev("CONTAINER|1\nSYS|kernel.randomize_va_space|0\n")
        self.assertEqual([s for s, _ in got], ["info"])

    def test_forwarding_on_docker_host_not_reported(self):
        text = UBUNTU_STOCK.replace("ip_forward|0", "ip_forward|1") + \
            "LINK|5: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN\n"
        self.assertIn(("low", "Kernel parameters to harden (2)"), ev(text))
        self.assertIn(("low", "Kernel parameters to harden (3)"),
                      ev(UBUNTU_STOCK.replace("ip_forward|0", "ip_forward|1")))

    def test_aslr_off_and_weak_hashes(self):
        text = UBUNTU_STOCK.replace("randomize_va_space|2", "randomize_va_space|0") \
            .replace("ENCRYPT_METHOD YESCRYPT", "ENCRYPT_METHOD MD5").replace("UMASK 022", "UMASK 000")
        med = [t for s, t in ev(text) if s == "medium"]
        self.assertEqual(len(med), 3, med)

    def test_promiscuous_interface_but_not_bridges(self):
        text = UBUNTU_STOCK + ("LINK|3: eth1: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500 state UP\n"
                                  "LINK|7: veth1@if6: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500 master docker0 state UP\n")
        self.assertIn(("medium", "Network interface in promiscuous mode: eth1"), ev(text))

    def test_real_script(self):
        res = hardening.run(make_ctx(FakeRemote(rules=[("CONTAINER|", fixture("hardening_sandbox_vm.txt"), 0)])))
        self.assertEqual(res.data["sysctl"]["fs.protected_symlinks"], "0")


if __name__ == "__main__":
    unittest.main()
