"""MySQL/MariaDB probe from the controller: is the server reachable from here, and which version does it report?

Right after the TCP connection a MySQL server sends a "greeting" (handshake) packet containing its
version, BEFORE any authentication. Reading it is passive: no login is attempted. If the controller's
address is not allowed, the server immediately sends an error packet ("Host '...' is not allowed to
connect"): the port is reachable anyway.

Wire format: 3-byte length (little endian) + 1-byte sequence number + payload.
Greeting payload: 0x0a (protocol version), then the server version terminated by 0x00, followed by a
4-byte connection id, 8 bytes of auth salt, 1 filler byte and 2 bytes of server capabilities. Bit 0x0800
(CLIENT_SSL) tells whether the server accepts TLS (verified on MySQL 8.0 with TLS enabled and with an
empty tls_version). Error payload: 0xff, 2-byte code, then the message.
"""
from __future__ import annotations

import socket

CLIENT_SSL = 0x0800


def parse_greeting(data: bytes) -> dict:
    """First server packet -> {"kind": "greeting"|"error"|"?", ...}. Pure function."""
    if len(data) < 5:
        return {"kind": "?"}
    n = int.from_bytes(data[:3], "little")
    payload = data[4:4 + n]
    if payload[:1] == b"\x0a":
        end = payload.find(b"\x00", 1)
        g = {"kind": "greeting", "version": payload[1:end if end > 0 else None].decode("ascii", "replace")}
        caps = payload[end + 14:end + 16] if end > 0 else b""
        if len(caps) == 2:
            g["ssl"] = bool(int.from_bytes(caps, "little") & CLIENT_SSL)
        return g
    if payload[:1] == b"\xff" and len(payload) >= 3:
        msg = payload[3:]
        if msg[:1] == b"#":          # some errors carry a 5-character SQLSTATE code after '#'
            msg = msg[6:]
        return {"kind": "error", "code": int.from_bytes(payload[1:3], "little"),
                "message": msg.decode("utf-8", "replace")}
    return {"kind": "?"}


def probe(host: str, port: int = 3306, timeout: float = 4.0) -> dict:
    """{"reachable": bool, ...greeting}. reachable=False if the connection fails (filtered/closed)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = b""
            while len(data) < 4 or len(data) < 4 + int.from_bytes(data[:3], "little"):
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
    except OSError:
        return {"reachable": False}
    return {"reachable": True, **parse_greeting(data)}
