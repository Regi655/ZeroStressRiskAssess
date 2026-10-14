"""DNS probes from the controller: how the target's DNS server looks from OUTSIDE.

A minimal client is implemented here instead of calling `dig`, which may be missing on the controller
and whose text output changes between versions. The DNS wire format (RFC 1035) is stable: a 12-byte
header, the question and the records; three probes need only the standard library.

The three probes:
  - recursion: query a name the server does NOT host (www.example.com) with the RD bit set. An answer
    with RA ("recursion available") and no refusal means an open resolver for us, usable for
    amplification attacks if reachable from the Internet;
  - zone transfer (AXFR): request the WHOLE zone over TCP. If it is returned, anyone in our position
    can download every name in the zone, including internal ones;
  - version: the CHAOS TXT "version.bind" query. BIND, Unbound and dnsmasq disclose their version
    unless it has been hidden.

The probes are passive (one query each, no load) and are sent only to the authorised target.
"""
from __future__ import annotations

import random
import socket
import struct

TYPE_A, TYPE_SOA, TYPE_TXT, TYPE_AXFR = 1, 6, 16, 252
CLASS_IN, CLASS_CH = 1, 3
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED", 9: "NOTAUTH"}
RECURSION_PROBE = "www.example.com"   # domain reserved for examples (RFC 2606): never served by the target


class DnsError(Exception):
    pass


def build_query(name: str, qtype: int, qclass: int = CLASS_IN, rd: bool = True, qid: int | None = None) -> bytes:
    qid = random.randint(0, 0xFFFF) if qid is None else qid
    header = struct.pack("!HHHHHH", qid, 0x0100 if rd else 0, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.strip(".").split(".") if p) + b"\0"
    return header + qname + struct.pack("!HH", qtype, qclass)


def parse_header(data: bytes) -> dict:
    if len(data) < 12:
        raise DnsError("response too short")
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    return {"id": qid, "qr": bool(flags & 0x8000), "aa": bool(flags & 0x0400), "tc": bool(flags & 0x0200),
            "rd": bool(flags & 0x0100), "ra": bool(flags & 0x0080), "rcode": RCODES.get(flags & 0xF, str(flags & 0xF)),
            "qd": qd, "an": an, "ns": ns, "ar": ar}


def read_name(data: bytes, off: int) -> tuple:
    """(name, offset after the name). Handles compression (0xC0 pointers): a name already present in a
    DNS message is referenced by a pointer to its first occurrence.
    """
    labels, jumped, end, seen = [], False, off, 0
    while True:
        if off >= len(data) or seen > 128:   # protection against malformed messages and pointer loops
            raise DnsError("malformed name")
        seen += 1
        n = data[off]
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                raise DnsError("truncated pointer")
            if not jumped:
                end = off + 2
            off, jumped = ((n & 0x3F) << 8) | data[off + 1], True
            continue
        if n == 0:
            return ".".join(labels) + ".", (end if jumped else off + 1)
        labels.append(data[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n


def parse_message(data: bytes) -> tuple:
    """(header, list of answer records). Each record: (name, type, rdata)."""
    h = parse_header(data)
    off = 12
    for _ in range(h["qd"]):          # the question section may be absent (Unbound, in REFUSED answers)
        _, off = read_name(data, off)
        off += 4
    records = []
    for _ in range(h["an"]):
        name, off = read_name(data, off)
        if off + 10 > len(data):
            raise DnsError("truncated record")
        rtype, _, _, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        records.append((name, rtype, data[off:off + rdlen]))
        off += rdlen
    return h, records


def _txt(rdata: bytes) -> str:
    out, i = [], 0
    while i < len(rdata):
        n = rdata[i]
        out.append(rdata[i + 1:i + 1 + n].decode("utf-8", "replace"))
        i += 1 + n
    return "".join(out)


def _family(host: str, port: int, kind):
    return socket.getaddrinfo(host, port, type=kind)[0]


def udp_query(host: str, name: str, qtype: int, qclass: int = CLASS_IN, rd: bool = True,
              port: int = 53, timeout: float = 3.0):
    """Single UDP query. None if the server does not answer in time (filtered or down)."""
    q = build_query(name, qtype, qclass, rd)
    fam, kind, proto, _, addr = _family(host, port, socket.SOCK_DGRAM)
    with socket.socket(fam, kind, proto) as s:
        s.settimeout(timeout)
        try:
            s.sendto(q, addr)
            while True:
                data, _ = s.recvfrom(4096)
                if data[:2] == q[:2]:         # same ID as the query: this is our answer
                    return parse_message(data)
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None


def probe_recursion(host: str, port: int = 53, timeout: float = 3.0) -> dict:
    r = udp_query(host, RECURSION_PROBE, TYPE_A, port=port, timeout=timeout)
    if r is None:
        return {"answered": False, "open": False}
    h, _ = r
    # Recursion offered = the server sets "ra" and does not refuse. SERVFAIL counts: it TRIED to resolve
    # on our behalf (failing only because it has no Internet access, as in an isolated lab).
    is_open = h["ra"] and h["rcode"] != "REFUSED" and not h["aa"]
    return {"answered": True, "open": is_open, "rcode": h["rcode"], "ra": h["ra"]}


def probe_version(host: str, port: int = 53, timeout: float = 3.0):
    """The version.bind text, or None if hidden, refused or unanswered."""
    r = udp_query(host, "version.bind", TYPE_TXT, CLASS_CH, rd=False, port=port, timeout=timeout)
    if r is None:
        return None
    h, records = r
    txt = [_txt(rd) for _, t, rd in records if t == TYPE_TXT]
    return txt[0] if h["rcode"] == "NOERROR" and txt else None


def probe_axfr(host: str, zone: str, port: int = 53, timeout: float = 5.0, max_records: int = 20000) -> dict:
    """Zone transfer over TCP. allowed=True only if the zone is actually returned (SOA ... SOA)."""
    q = build_query(zone, TYPE_AXFR, rd=False)
    fam, kind, proto, _, addr = _family(host, port, socket.SOCK_STREAM)
    names, count, soa = [], 0, 0
    try:
        with socket.socket(fam, kind, proto) as s:
            s.settimeout(timeout)
            s.connect(addr)
            s.sendall(struct.pack("!H", len(q)) + q)
            buf = b""
            while soa < 2 and count < max_records:
                while len(buf) < 2 or len(buf) < 2 + struct.unpack("!H", buf[:2])[0]:
                    chunk = s.recv(65536)
                    if not chunk:
                        raise EOFError
                    buf += chunk
                n = struct.unpack("!H", buf[:2])[0]
                msg, buf = buf[2:2 + n], buf[2 + n:]
                h, records = parse_message(msg)
                if h["rcode"] != "NOERROR" or (count == 0 and not records):
                    return {"allowed": False, "rcode": h["rcode"]}
                for name, rtype, _ in records:
                    count += 1
                    soa += rtype == TYPE_SOA
                    if name not in names:
                        names.append(name)
    except EOFError:
        pass                                   # connection closed by the server: refusal or end of transfer
    except (socket.timeout, OSError, DnsError) as exc:
        return {"allowed": False, "error": type(exc).__name__}
    return {"allowed": soa >= 1 and count > 0, "records": count, "names": names, "complete": soa >= 2}
