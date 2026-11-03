"""DNS: probe client (dnsprobe) and the check with role detection.

REAL data from the ISP lab, recorded with BIND 9.18.39, Unbound 1.19.2 and dnsmasq 2.91:
  - fixtures/named_checkconf_*.txt: output of `named-checkconf -p` for ns1, ns2 and the stock Ubuntu
    configuration;
  - fixtures/dns_wire.json: the BYTES of the real answers (recursion, version.bind, AXFR).
A small fake server started by the test sends those bytes back, so the network side of the client
(UDP, TCP, multi-message AXFR) is exercised without BIND.
"""
import json
import socket
import socketserver
import struct
import threading
import unittest
from unittest import mock

from zerostressriskassess import dnsprobe as dp
from zerostressriskassess.scanners import dns
from tests.fakes import FakeRemote, fixture, make_ctx

WIRE = {k: bytes.fromhex(v) for k, v in json.loads(fixture("dns_wire.json")).items() if not k.startswith("_")}
SS = 'udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("%s",pid=10,fd=3))'


# ---------------------------------------------------------------------------- client: real messages
class RealMessagesTest(unittest.TestCase):
    def test_recursion_offered_ns1(self):
        h, _ = dp.parse_message(WIRE["ns1_recursion"])
        self.assertEqual((h["ra"], h["rcode"]), (True, "SERVFAIL"))

    def test_recursion_refused_ns2_and_unbound(self):
        for k in ("ns2_recursion", "unbound_refused_from_outside"):
            h, _ = dp.parse_message(WIRE[k])
            self.assertEqual((h["ra"], h["rcode"]), (False, "REFUSED"), k)

    def test_version(self):
        h, rr = dp.parse_message(WIRE["ns1_version"])
        self.assertEqual(dp._txt(rr[0][2]), "9.18.39-0ubuntu0.24.04.7-Ubuntu")

    def test_circular_pointer_does_not_hang(self):
        evil = struct.pack("!HHHHHH", 1, 0x8180, 0, 1, 0, 0) + b"\xc0\x0c" + b"\0" * 10
        with self.assertRaises(dp.DnsError):
            dp.parse_message(evil)


# ---------------------------------------------------------------------------- client: real network
def _qname(data):
    return dp.read_name(data, 12)[0]


class _Udp(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        name = _qname(data)
        reply = {"version.bind.": self.server.wire.get("version"),
                 dp.RECURSION_PROBE + ".": self.server.wire.get("recursion")}.get(name)
        if reply:
            sock.sendto(data[:2] + reply[2:], self.client_address)   # same ID as the query


class _Tcp(socketserver.BaseRequestHandler):
    def handle(self):
        n = struct.unpack("!H", self.request.recv(2))[0]
        data = self.request.recv(n)
        stream = self.server.wire.get("axfr", b"")
        # The recording already holds the messages with their length prefix: only the ID is changed.
        out, i = b"", 0
        while i + 2 <= len(stream):
            m = struct.unpack("!H", stream[i:i + 2])[0]
            msg = stream[i + 2:i + 2 + m]
            out += stream[i:i + 2] + data[:2] + msg[2:]
            i += 2 + m
        self.request.sendall(out)


class FakeServer:
    """UDP + TCP on 127.0.0.1, free port, with the recorded answers."""

    def __init__(self, wire):
        self.udp = socketserver.ThreadingUDPServer(("127.0.0.1", 0), _Udp)
        self.port = self.udp.server_address[1]
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        self.tcp = socketserver.ThreadingTCPServer(("127.0.0.1", self.port), _Tcp)
        for s in (self.udp, self.tcp):
            s.wire = wire
            threading.Thread(target=s.serve_forever, daemon=True).start()

    def close(self):
        for s in (self.udp, self.tcp):
            s.shutdown()
            s.server_close()


class NetworkTest(unittest.TestCase):
    def setUp(self):
        try:
            self.ns1 = FakeServer({"recursion": WIRE["ns1_recursion"], "version": WIRE["ns1_version"],
                                    "axfr": WIRE["ns1_axfr_tcp"]})
            self.ns2 = FakeServer({"recursion": WIRE["ns2_recursion"], "axfr": WIRE["ns2_axfr_tcp"]})
        except OSError as exc:   # port already used in UDP or TCP: rare, the test is skipped
            self.skipTest(f"port not available: {exc}")

    def tearDown(self):
        self.ns1.close()
        self.ns2.close()

    def test_ns1(self):
        p = self.ns1.port
        self.assertTrue(dp.probe_recursion("127.0.0.1", p)["open"])
        self.assertEqual(dp.probe_version("127.0.0.1", p), "9.18.39-0ubuntu0.24.04.7-Ubuntu")
        a = dp.probe_axfr("127.0.0.1", "isp-lab.example", p)
        self.assertEqual((a["allowed"], a["records"], a["complete"]), (True, 13, True))
        self.assertIn("backup-interno.isp-lab.example.", a["names"])

    def test_ns2(self):
        p = self.ns2.port
        self.assertFalse(dp.probe_recursion("127.0.0.1", p)["open"])
        self.assertIsNone(dp.probe_version("127.0.0.1", p, timeout=0.5))   # no answer
        self.assertFalse(dp.probe_axfr("127.0.0.1", "isp-lab.example", p)["allowed"])

    def test_server_down(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            free = s.getsockname()[1]
        self.assertEqual(dp.probe_recursion("127.0.0.1", free, timeout=0.5), {"answered": False, "open": False})
        self.assertFalse(dp.probe_axfr("127.0.0.1", "x.example", free, timeout=0.5)["allowed"])


# ---------------------------------------------------------------------------- real configurations
class ConfigurationsTest(unittest.TestCase):
    def test_ns1(self):
        f = dns.bind_facts(fixture("named_checkconf_ns1.txt"))
        self.assertEqual(f["recursion"], "yes")
        self.assertEqual(f["allow_recursion"], ["any"])
        self.assertEqual([z["name"] for z in f["zones"]], ["isp-lab.example", "cliente1.example"])

    def test_ns2(self):
        f = dns.bind_facts(fixture("named_checkconf_ns2.txt"))
        self.assertEqual((f["recursion"], f["allow_transfer"], f["version_hidden"]), ("no", ["none"], True))
        self.assertEqual(f["zones"][0]["type"], "secondary")

    def test_ubuntu_default_is_not_authoritative(self):
        # localhost, 127.in-addr.arpa... are STOCK "type master" zones: they do not make BIND authoritative.
        self.assertEqual(dns.bind_facts(fixture("named_checkconf_ubuntu_default.txt"))["zones"], [])

    def test_views(self):
        f = dns.bind_facts('view "external" { zone "a.example" { type primary; file "x"; }; };')
        self.assertEqual(f["zones"][0]["name"], "a.example")

    def test_unbound(self):
        f = dns.unbound_facts("server:\n  access-control: 0.0.0.0/0 allow # wrong\n  module-config: \"iterator\"\n")
        self.assertEqual(f["acl"], [("0.0.0.0/0", "allow")])
        self.assertFalse(f["validator"])

    def test_dnsmasq_command_line(self):
        self.assertFalse(dns.dnsmasq_facts("no-resolv\nserver=1.2.3.4\n")["restricted"])
        self.assertTrue(dns.dnsmasq_facts("no-resolv\n", "dnsmasq --listen-address=10.0.0.1")["restricted"])

    def test_listening(self):
        d = dns.dns_listeners('udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=5,fd=1))\n'
                              'tcp LISTEN 0 10 0.0.0.0:5353 0.0.0.0:* users:(("avahi",pid=6,fd=1))')
        self.assertEqual(d, {"systemd-resolve": {"pid": 5, "addrs": {"127.0.0.53"}}})


# ---------------------------------------------------------------------------- whole check
LAB_RESOLVER = ("server:\n    interface: 0.0.0.0\n    access-control: 0.0.0.0/0 refuse\n"
                "    access-control: 172.28.8.0/24 allow\n    module-config: \"iterator\"\n")
CPE = "no-resolv\nserver=172.28.7.20\ncache-size=1000\n"


def scan(proc, rules, rec, ver=None, axfr=None):
    """Runs the check with the external probes replaced by the results recorded on the lab."""
    ss = fixture("ss_no_ptrace.txt") if any(r[0].startswith("ps -eo") for r in rules) else SS % proc
    rem = FakeRemote(host="172.28.7.99", rules=[("ss -Htulpn", ss, 0)] + rules)
    with mock.patch.object(dp, "probe_recursion", return_value=rec), \
            mock.patch.object(dp, "probe_version", return_value=ver), \
            mock.patch.object(dp, "probe_axfr", side_effect=lambda h, z: (axfr or {}).get(z, {"allowed": False})):
        res = dns.run(make_ctx(rem))
    return res, {(f.severity, f.title) for f in res.findings}


OPEN = {"answered": True, "open": True, "rcode": "SERVFAIL", "ra": True}
REFUSED = {"answered": True, "open": False, "rcode": "REFUSED", "ra": False}


class ScannerTest(unittest.TestCase):
    def test_ns1_every_error_once(self):
        res, got = scan("named", [("cmdline", "named -u bind", 0),
                                  ("named-checkconf -p", fixture("named_checkconf_ns1.txt"), 0)],
                        OPEN, "9.18.28", {"isp-lab.example": {"allowed": True, "records": 13,
                                                              "names": ["isp-lab.example.", "vpn-amministrazione.isp-lab.example."]}})
        high = sorted(t for s, t in got if s == "high")
        self.assertEqual(high, [
            "BIND: zone transfer of 'cliente1.example' allowed to anyone",   # not confirmed: kept from the config
            "DNS: OPEN resolver - answers recursive queries from the controller",
            "DNS: zone transfer of 'isp-lab.example' SUCCEEDED from the controller (13 records)"])
        self.assertIn(("medium", "BIND is both authoritative and a recursive resolver"), got)
        self.assertIn(("low", "DNS: software version exposed: 9.18.28"), got)
        axfr = [f for f in res.findings if "SUCCEEDED" in f.title][0]
        self.assertIn("vpn-amministrazione", axfr.detail)
        self.assertIn("Cause in the configuration: allow-transfer { any; }", axfr.detail)

    def test_ns2_well_configured(self):
        _, got = scan("named", [("cmdline", "named -u bind", 0),
                                ("named-checkconf -p", fixture("named_checkconf_ns2.txt"), 0)],
                      REFUSED, "not available")
        self.assertEqual({s for s, _ in got}, {"info"})   # not even the fake version counts

    def test_resolver_well_closed_but_without_dnssec(self):
        _, got = scan("unbound", [("cmdline", "unbound", 0), ("unbound.conf", LAB_RESOLVER, 0)], REFUSED)
        self.assertEqual({(s, t) for s, t in got if s != "info"}, {("medium", "Unbound: DNSSEC validation not enabled")})
        self.assertIn(("info", "DNS: recursion refused to the controller (REFUSED)"), got)

    def test_open_cpe(self):
        res, got = scan("dnsmasq", [("cmdline", "dnsmasq --conf-file=/etc/dnsmasq.conf", 0), ("dnsmasq.conf", CPE, 0)],
                        OPEN, "dnsmasq-2.86")
        self.assertIn(("high", "DNS: OPEN resolver - answers recursive queries from the controller"), got)
        self.assertNotIn(("medium", "dnsmasq answers on all interfaces, without network restrictions"), got)  # confirmed
        self.assertIn("dnsmasq without interface", [f for f in res.findings if "OPEN" in f.title][0].detail)

    def test_firewall_configuration_findings_remain(self):
        _, got = scan("named", [("cmdline", "named -u bind", 0),
                                ("named-checkconf -p", fixture("named_checkconf_ns1.txt"), 0)],
                      {"answered": False, "open": False})
        self.assertIn(("high", "BIND: recursion allowed to ANYONE in the configuration (allow-recursion any)"), got)
        self.assertIn(("high", "BIND: zone transfer of 'isp-lab.example' allowed to anyone"), got)

    def test_stock_bind_recursion_local_only(self):
        # Stock Ubuntu: recursion on WITHOUT allow-recursion (default: localnets) -> if the controller
        # gets an answer it is because it is on the local network: medium, not "open".
        _, got = scan("named", [("cmdline", "named -u bind", 0),
                                ("named-checkconf -p", fixture("named_checkconf_ubuntu_default.txt"), 0)], OPEN)
        self.assertIn(("medium", "DNS: recursion granted to the controller (which is among the allowed clients)"), got)

    def test_only_systemd_resolved(self):
        rem = FakeRemote(rules=[("ss -Htulpn", 'udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* '
                                               'users:(("systemd-resolve",pid=5,fd=1))', 0)])
        with mock.patch.object(dp, "probe_recursion") as p:
            res = dns.run(make_ctx(rem))
        self.assertEqual(res.status, "skipped")
        p.assert_not_called()   # no network probes if DNS is not exposed

    def test_no_dns(self):
        self.assertEqual(dns.run(make_ctx(FakeRemote())).status, "skipped")


# ---------------------------------------------------------------------------- container without CAP_SYS_PTRACE
class NoPtraceTest(unittest.TestCase):
    """ISP lab, 13 Oct: in Docker root lacks CAP_SYS_PTRACE and `ss -p` does not show named (it runs as
    'bind'): the check reported "No DNS server" on an open BIND. REAL fixtures, reproduced with
    `capsh --drop=cap_sys_ptrace -- -c 'ss -Htulpn'`."""

    def test_named_identified_from_ps(self):
        _, got = scan("named", [("ps -eo pid=,comm=", fixture("ps_no_ptrace.txt"), 0),
                                ("cmdline", "named -u bind", 0),
                                ("named-checkconf -p", fixture("named_checkconf_ns1.txt"), 0)],
                      OPEN, None, {"isp-lab.example": {"allowed": True, "records": 13, "names": []}})
        self.assertIn(("high", "DNS: OPEN resolver - answers recursive queries from the controller"), got)
        self.assertIn(("info", "DNS: process identified from the process list, not from the sockets"), got)

    def test_nmap_only_at_least_external_probes(self):
        rem = FakeRemote(host="172.28.7.99")
        ctx = make_ctx(rem)
        ctx.cache["nmap_open"] = [{"port": 53, "proto": "tcp", "service": "domain"}]
        with mock.patch.object(dp, "probe_recursion", return_value=OPEN) as p, \
                mock.patch.object(dp, "probe_version", return_value=None):
            res = dns.run(ctx)
        p.assert_called_once()
        self.assertIn("DNS: OPEN resolver - answers recursive queries from the controller", [f.title for f in res.findings])


if __name__ == "__main__":
    unittest.main()
