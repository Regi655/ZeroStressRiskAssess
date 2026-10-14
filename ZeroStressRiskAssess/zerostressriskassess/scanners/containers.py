"""Docker: who can control it, how containers are started, what they expose.

Docker is a security concern for the HOST, not only for the containers:
  - anyone who can use Docker (docker group, accessible socket, network API) can start a container
    with the host root filesystem mounted: effectively ROOT on the machine;
  - a container started with --privileged, with the Docker socket mounted, or with the host root
    mounted is NOT isolated: compromising it means reaching the host;
  - ports published by Docker BYPASS UFW: Docker writes its rules into the nat and FORWARD tables,
    which UFW does not manage. Verified in the development lab: with UFW active and "deny incoming",
    a host port was blocked while port 8080 published by a container was not.
"""
from __future__ import annotations

import json
import re

from ..models import ScanResult

INSPECT_FMT = ("{{.Name}}|{{.HostConfig.Privileged}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.PidMode}}|"
               "{{json .HostConfig.CapAdd}}|{{json .Mounts}}|{{json .HostConfig.PortBindings}}|{{.Config.User}}|"
               "{{.Config.Image}}")
CAP_HIGH = {"ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "DAC_READ_SEARCH", "SYS_RAWIO", "CAP_SYS_ADMIN",
            "CAP_SYS_MODULE", "CAP_SYS_PTRACE", "CAP_DAC_READ_SEARCH", "CAP_SYS_RAWIO", "CAP_ALL"}
SENSITIVE_MOUNTS = ("/", "/etc", "/root", "/home", "/var/run", "/run", "/proc", "/sys", "/boot", "/var/lib/docker")
SOCKETS = ("/var/run/docker.sock", "/run/docker.sock")
LOCAL_IPS = ("127.", "::1", "localhost")


def parse_inspect(text: str) -> list:
    """Output of `docker inspect --format INSPECT_FMT` -> [container]. Pure function."""
    out = []
    for line in text.splitlines():
        p = line.split("|", 8)
        if len(p) != 9:
            continue
        try:
            caps = json.loads(p[4]) or []
            mounts = json.loads(p[5]) or []
            ports = json.loads(p[6]) or {}
        except ValueError:
            continue
        published = []
        for cport, binds in ports.items():
            for b in binds or []:
                published.append({"container": cport, "host_ip": b.get("HostIp", ""), "host_port": b.get("HostPort", "")})
        out.append({"name": p[0].lstrip("/"), "privileged": p[1] == "true", "network": p[2], "pid": p[3],
                    "caps": caps, "mounts": [(m.get("Source", ""), m.get("RW", True)) for m in mounts],
                    "published": published, "user": p[7], "image": p[8]})
    return out


def check_container(res, c: dict):
    n = f"'{c['name']}' ({c['image']})"
    if c["privileged"]:
        res.add("high", f"Privileged container: {n}",
                "--privileged gives the container all host devices and capabilities: there is no isolation.")
    for src, rw in c["mounts"]:
        if src in SOCKETS:
            res.add("high", f"Docker socket mounted in container {n}",
                    "Whoever controls the container can start others with the host root mounted: equivalent to root on the host.")
        elif src.rstrip("/") in [m.rstrip("/") for m in SENSITIVE_MOUNTS] or src == "/":
            res.add("high", f"Host system directory mounted in the container {n}: {src}",
                    ("read-write" if rw else "read-only") + ": host files such as /etc/shadow or SSH keys can be read "
                    "(or modified) from the container.")
    host_ns = [k for k, v in (("network", c["network"]), ("processes", c["pid"])) if v == "host"]
    if host_ns:
        res.add("medium", f"Container {n} shares with the host: {', '.join(host_ns)}",
                "With --network host it sees every local service of the host; with --pid host it sees (and can signal) its processes.")
    risky = sorted(set(c["caps"]) & CAP_HIGH)
    if risky:
        res.add("high", f"Container {n} with dangerous capabilities: {', '.join(risky)}",
                "SYS_ADMIN, SYS_MODULE, SYS_PTRACE... are the classic container escape routes.")


def run(ctx) -> ScanResult:
    res, rem = ScanResult("containers"), ctx.rem
    has_docker = rem.run("command -v docker || test -S /var/run/docker.sock || test -S /run/docker.sock").rc == 0
    if rem.run("command -v podman").rc == 0:
        res.add("info", "Podman present: not covered by this check")
    if not has_docker:
        return res.skip("Docker not present") if not res.findings else res

    # ---- who can control Docker
    grp = rem.run("getent group docker").out.strip().split(":")
    members = [m for m in (grp[3].split(",") if len(grp) >= 4 else []) if m]
    if members:
        res.add("high", f"Users in the docker group (equivalent to root): {', '.join(members)}",
                "Members of the docker group can run `docker run -v /:/host ...` and read or modify the whole "
                "host without a password. It must be treated as administrative access.")
    st = rem.run("stat -L -c '%a|%U|%G|%n' /var/run/docker.sock /run/docker.sock 2>/dev/null", sudo=True).out
    for line in sorted(set(st.splitlines()))[:1]:
        mode, owner, group, path = (line.split("|") + ["", "", "", ""])[:4]
        if mode.isdigit() and int(mode, 8) & 0o002:
            res.add("critical", f"Docker socket writable by ANYONE: {path} (mode {mode})",
                    "Any user on the system controls Docker and therefore becomes root.")
        elif mode.isdigit() and group not in ("docker", "root"):
            res.add("medium", f"Docker socket with an unusual group: {path} ({owner}:{group}, mode {mode})")

    # ---- network API
    cmd = rem.run("for p in $(pgrep -x dockerd); do tr '\\0' ' ' < /proc/$p/cmdline; echo; done; "
                  "cat /etc/docker/daemon.json 2>/dev/null", sudo=True).out
    listening = rem.run("ss -Hltn", sudo=True).out
    tcp_api = re.findall(r"tcp://[^\s\"',\]]+", cmd)
    if tcp_api or re.search(r":2375\s", listening):
        tls = "--tlsverify" in cmd or '"tlsverify": true' in cmd.replace(" ", "").replace('":true', '": true')
        if not tls:
            res.add("critical", "Docker API listening on the network WITHOUT TLS authentication",
                    f"{', '.join(tcp_api) or 'port 2375'}: anyone who reaches it controls Docker and therefore the host.")
        else:
            res.add("info", "Docker API on the network with TLS and client verification", ", ".join(tcp_api))

    # ---- running containers
    ids = rem.run("docker ps -q", sudo=True, timeout=60).out.split()
    if not ids:
        res.add("info", "Docker present, no running containers")
        return res
    containers = parse_inspect(rem.run(f"docker inspect --format '{INSPECT_FMT}' {' '.join(ids[:100])}",
                                       sudo=True, timeout=120).out)
    res.data["containers"] = [c["name"] for c in containers]
    for c in containers:
        check_container(res, c)

    exposed = [(c, p) for c in containers for p in c["published"] if not p["host_ip"].startswith(LOCAL_IPS)]
    if exposed:
        shown = ", ".join(f"{p['host_port']}->{c['name']}:{p['container']}" for c, p in exposed[:15])
        ufw_on = "Status: active" in rem.run("ufw status", sudo=True).out
        if ufw_on:
            res.add("high", "Docker-published ports that BYPASS UFW: " + shown,
                    "UFW is active but does not filter these ports: Docker writes its rules into the nat and FORWARD tables, "
                    "which UFW does not manage (verified). Publish on 127.0.0.1 only (-p 127.0.0.1:PORT:PORT) or "
                    "filter in the DOCKER-USER chain.")
        else:
            res.add("info", "Ports published by Docker on all interfaces: " + shown)
    res.add("info", f"Running containers: {len(containers)}", ", ".join(c["name"] for c in containers[:20]))
    return res
