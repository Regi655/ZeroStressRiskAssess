"""File capabilities, Docker, disk encryption and Secure Boot.

REAL fixtures collected in the development sandbox:
  - getcap_sandbox.txt: python3 with cap_setuid (verified: os.setuid(0) -> uid 0), a copy of tar with
    cap_dac_read_search, a program with cap_net_bind_service, and gst-ptp-helper (packaged);
  - docker_inspect_sandbox.txt: seven real containers (privileged, socket mounted, host root, host
    network/pid, CAP_SYS_ADMIN, port published on all interfaces, local-only port);
  - ufw_status_active.txt: UFW active with "deny incoming", with which the container's port 8080 stayed
    reachable from another network namespace (the host's 8081 did not);
  - platform_vm_sandbox.txt: the sandbox VM (BIOS, unencrypted disk).
The LUKS and Secure Boot on/off cases are SYNTHETIC, in the format of lsblk -P and od: in this sandbox the
kernel has no device-mapper and there is no UEFI.
"""
import unittest

from zerostressriskassess.scanners import containers, permissions, platform
from tests.fakes import FakeRemote, fixture, make_ctx

PASSWD = "root:x:0:0:root:/root:/bin/bash\n"
GST = "/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper"


class CapabilitiesTest(unittest.TestCase):
    def setUp(self):
        rem = FakeRemote(default_rc=1, rules=[
            ("cat /etc/passwd", PASSWD, 0),
            ("command -v getcap", "/usr/sbin/getcap", 0),
            ("xargs -0 -r getcap", fixture("getcap_sandbox.txt"), 0),
            (f"dpkg -S {GST}", f"gstreamer1.0-plugins-base: {GST}", 0),   # packaged
        ])
        self.res = permissions.run(make_ctx(rem))
        self.by = {f.detail.split(":")[0]: (f.severity, f.title) for f in self.res.findings if "cap_" in f.detail}

    def test_interpreter_with_setuid_critical(self):
        self.assertEqual(self.by["/opt/capdemo/python3"][0], "critical")

    def test_reads_any_file(self):
        self.assertEqual(self.by["/usr/local/bin/backup-tool"],
                         ("high", "Capability that reads ANY file (cap_dac_read_search)"))

    def test_harmless_outside_package_low_and_packaged_nothing(self):
        self.assertEqual(self.by["/opt/capdemo/webserver"][0], "low")
        self.assertNotIn(GST, self.by)

    def test_old_format(self):
        self.assertEqual(permissions.parse_getcap("/usr/bin/ping = cap_net_raw+ep"), [("/usr/bin/ping", {"cap_net_raw"})])

    def test_known_auth_pam_tool(self):   # SUID from mariadb-server, seen in the ISP lab
        self.assertIn("auth_pam_tool", permissions.KNOWN_SUID)


def docker_scan(extra=(), ufw="active"):
    rem = FakeRemote(default_rc=1, rules=list(extra) + [
        ("command -v docker", "/usr/bin/docker", 0),
        ("getent group docker", "docker:x:996:developer\n", 0),
        ("stat -L -c", "660|root|docker|/var/run/docker.sock\n", 0),
        ("pgrep -x dockerd", "dockerd \n", 0),
        ("docker ps -q", "a1\nb2\n", 0),
        ("docker inspect", fixture("docker_inspect_sandbox.txt"), 0),
        ("ufw status", fixture("ufw_status_active.txt") if ufw == "active" else "Status: inactive\n", 0),
    ])
    res = containers.run(make_ctx(rem))
    return res, {(f.severity, f.title) for f in res.findings}


class DockerTest(unittest.TestCase):
    def test_real_containers(self):
        _, got = docker_scan()
        high = sorted(t for s, t in got if s == "high")
        self.assertEqual(high, sorted([
            "Users in the docker group (equivalent to root): developer",
            "Container 'sysadmin' (lab/busybox:1) with dangerous capabilities: CAP_SYS_ADMIN",
            "Host system directory mounted in the container 'host-root' (lab/busybox:1): /",
            "Docker socket mounted in container 'with-socket' (lab/busybox:1)",
            "Privileged container: 'privileged' (lab/busybox:1)",
            "Docker-published ports that BYPASS UFW: 8080->web:80/tcp"]))
        self.assertIn(("medium", "Container 'host-net' (lab/busybox:1) shares with the host: network, processes"), got)
        self.assertFalse([t for _, t in got if "local-only" in t and "BYPASS" in t])   # 127.0.0.1: fine

    def test_without_ufw_ports_are_info_only(self):
        _, got = docker_scan(ufw="inactive")
        self.assertIn(("info", "Ports published by Docker on all interfaces: 8080->web:80/tcp"), got)

    def test_network_api_without_tls(self):
        _, got = docker_scan(extra=[("pgrep -x dockerd", "dockerd -H fd:// -H tcp://0.0.0.0:2375 \n", 0)])
        self.assertIn(("critical", "Docker API listening on the network WITHOUT TLS authentication"), got)

    def test_socket_open_to_everyone(self):
        _, got = docker_scan(extra=[("stat -L -c", "666|root|docker|/var/run/docker.sock\n", 0)])
        self.assertIn(("critical", "Docker socket writable by ANYONE: /var/run/docker.sock (mode 666)"), got)

    def test_docker_missing(self):
        self.assertEqual(containers.run(make_ctx(FakeRemote(default_rc=1))).status, "skipped")


LUKS = ('CHAIN|NAME="vgubuntu-root" TYPE="lvm" FSTYPE="ext4"\n'
        'CHAIN|NAME="dm_crypt-0" TYPE="crypt" FSTYPE="LVM2_member"\n'
        'CHAIN|NAME="nvme0n1p3" TYPE="part" FSTYPE="crypto_LUKS"\n'
        'CHAIN|NAME="nvme0n1" TYPE="disk" FSTYPE=""\n')
LAPTOP = "CONTAINER|0\nHV|0\nVIRT|none\nVENDOR|Acer\nCHASSIS|10\nBAT|1\nROOT|/dev/mapper/vgubuntu-root\nEFI|yes\n"


class PlatformTest(unittest.TestCase):
    def ev(self, text):
        return {(s, t) for s, t, _ in platform.evaluate(platform.parse(text))}

    def test_real_vm(self):
        got = self.ev(fixture("platform_vm_sandbox.txt"))
        self.assertEqual({s for s, _ in got} - {"info"}, set())   # on a VM none of this weighs
        self.assertTrue([t for _, t in got if "container" in t or "virtual machine" in t])

    def test_unencrypted_laptop_and_secure_boot_off(self):
        got = self.ev(LAPTOP.replace("ROOT|/dev/mapper/vgubuntu-root", "ROOT|/dev/nvme0n1p2")
                      + 'CHAIN|NAME="nvme0n1p2" TYPE="part" FSTYPE="ext4"\nSB| 6 0 0 0 0\n')
        self.assertIn(("high", "System disk NOT encrypted"), got)
        self.assertIn(("medium", "Secure Boot DISABLED"), got)

    def test_encrypted_laptop_but_cleartext_swap(self):
        got = self.ev(LAPTOP + LUKS + "SB| 6 0 0 0 1\nSWAP|/dev/nvme0n1p4|partition\n"
                      'SWAPCHAIN|/dev/nvme0n1p4|NAME="nvme0n1p4" TYPE="part" FSTYPE="swap"\n'
                      "SWAP|/dev/zram0|partition\n")
        self.assertIn(("info", "System root on an encrypted disk (LUKS/dm-crypt)"), got)
        self.assertIn(("info", "Secure Boot enabled"), got)
        self.assertIn(("medium", "Swap NOT encrypted with an encrypted root: /dev/nvme0n1p4"), got)
        self.assertFalse([t for _, t in got if "zram" in t])   # zram lives in RAM

    def test_container(self):
        got = self.ev("CONTAINER|1\n")
        self.assertEqual(got, {("info", "Target is a container: disk encryption and Secure Boot concern the host")})

    def test_lsblk_without_argument_guarded(self):
        self.assertIn('[ -n "$src" ] && [ -b "$src" ]', platform.SCRIPT)


class Laptop081Test(unittest.TestCase):
    """Fixes of 0.8.1 from the REAL report of an Ubuntu 26.04 laptop (MySQL 8.4.11, sssd, snapd, Docker).
    getcap_laptop.txt is rebuilt from the report details (real paths and capabilities; the =ep/=p suffix
    does not appear in the report)."""

    def scan(self, modified=""):
        paths = [l.split()[0] for l in fixture("getcap_laptop.txt").splitlines()]
        rules = [("cat /etc/passwd", PASSWD, 0), ("command -v getcap", "/usr/sbin/getcap", 0),
                 ("xargs -0 -r getcap", fixture("getcap_laptop.txt"), 0)]
        for p in paths:
            pkg = "snapd" if "snap" in p else "iputils-ping" if "ping" in p else "sssd-common"
            rules.append((f"dpkg -S {p}", f"{pkg}: {p}", 0))
        rules.append(("dpkg -V sssd-common", f"??5??????   {modified}\n" if modified else "", 0))
        res = permissions.run(make_ctx(FakeRemote(default_rc=1, rules=rules)))
        return [(f.severity, f.title) for f in res.findings if "apabilit" in f.title]

    def test_known_packaged_programs_one_info_line(self):
        got = self.scan()
        self.assertEqual(got, [("info", "Capabilities on known system programs installed by packages (6)")])

    def test_modified_known_program_is_critical_again(self):
        got = self.scan(modified="/usr/libexec/sssd/ldap_child")
        self.assertIn(("critical", "Program with capability MODIFIED compared to its package"), got)
        self.assertIn(("info", "Capabilities on known system programs installed by packages (5)"), got)

    def test_containerd_excluded(self):
        # Verified with a real find: without the exclusion, a 777 directory in a containerd snapshot was
        # listed (on the laptop: 16 high and ~58 medium from the layers of the lab images).
        self.assertIn("-path /var/lib/containerd ", permissions.PRUNE)


if __name__ == "__main__":
    unittest.main()
