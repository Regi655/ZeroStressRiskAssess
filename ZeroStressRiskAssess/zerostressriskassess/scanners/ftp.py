"""FTP (vsftpd) from the inside: the configuration states what an anonymous user can do.

This complements nmap's ftp-anon script. With vsftpd configured with pasv_enable=NO, nmap reports
"anonymous login allowed" but cannot list the files ("PASV failed"), so it cannot tell that anonymous
users may also UPLOAD. From outside only what the protocol exposes is visible; the configuration is
always authoritative, and if a firewall blocks the controller this is the only remaining check.

vsftpd 3.0.5 defaults VERIFIED (configuration containing only listen=YES): anonymous login allowed
(anonymous_enable=YES by default), local users denied (local_enable=NO), no writes (write_enable=NO).
The configuration files shipped by Debian/Ubuntu and RHEL set different values, so the file actually
read counts and, where a line is missing, the built-in default applies.
"""
from __future__ import annotations

import shlex

from ..models import ScanResult
from ..validate import valid_path

DEFAULTS = {"anonymous_enable": "YES", "local_enable": "NO", "write_enable": "NO", "anon_upload_enable": "NO",
            "anon_mkdir_write_enable": "NO", "anon_other_write_enable": "NO", "ssl_enable": "NO",
            "chroot_local_user": "NO"}
CONF_PATHS = ("/etc/vsftpd.conf", "/etc/vsftpd/vsftpd.conf")
OTHER_FTPD = ("proftpd", "pure-ftpd", "in.ftpd")


def parse_conf(text: str) -> dict:
    """vsftpd.conf -> {option: value}, with built-in defaults for missing lines. Pure function."""
    conf = dict(DEFAULTS)
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        conf[k.strip().lower()] = v.strip()
    return conf


def yes(conf, key) -> bool:
    return conf.get(key, "NO").upper() in ("YES", "TRUE", "1")


def evaluate(conf: dict, writable: list, nmap_saw_anon: bool) -> list:
    """[(severity, title, detail)]. Pure function."""
    out = []
    if yes(conf, "anonymous_enable"):
        rights = [k for k in ("anon_upload_enable", "anon_mkdir_write_enable", "anon_other_write_enable")
                  if yes(conf, k)]
        if yes(conf, "write_enable") and rights:
            out.append(("high", "FTP: the anonymous user can WRITE to the server",
                        f"{', '.join(k + '=YES' for k in rights)} with write_enable=YES"
                        + (f"; writable directories under {conf.get('anon_root', '~ftp')}: {', '.join(writable[:10])}"
                           if writable else "")
                        + ". Anyone can upload files without a password: a drop point for malware or illegal material "
                        "in the name of the server owner." + (" anon_other_write_enable also allows "
                                                                  "deleting and renaming." if "anon_other_write_enable" in rights else "")))
        elif nmap_saw_anon:
            out.append(("info", "Anonymous FTP confirmed in the configuration (anonymous_enable=YES), read-only", ""))
        else:
            out.append(("medium", "Anonymous FTP enabled in the configuration (anonymous_enable=YES)",
                        "Not observed from the controller (firewall in between?) but enabled. If the line is missing, vsftpd "
                        "enables it BY DEFAULT."))
    if yes(conf, "local_enable"):
        if not yes(conf, "ssl_enable"):
            out.append(("medium", "FTP: system users with clear-text passwords (local_enable=YES, ssl_enable=NO)",
                        "The passwords travelling unencrypted are those of the system accounts: whoever "
                        "intercepts the traffic can then log in over SSH too. Enable ssl_enable or use SFTP."))
        if not yes(conf, "chroot_local_user"):
            out.append(("low", "FTP: local users not confined to their home directory (chroot_local_user=NO)",
                        "Over FTP they can browse the whole readable filesystem."))
    return out


def run(ctx) -> ScanResult:
    res, rem = ScanResult("ftp"), ctx.rem
    procs = rem.run("ps -eo pid=,comm=", sudo=True).out.split("\n")
    names = {p.split(None, 1)[1].strip(): p.split(None, 1)[0] for p in procs if len(p.split(None, 1)) == 2}
    if "vsftpd" not in names:
        others = [n for n in OTHER_FTPD if n in names]
        if others:
            res.add("info", f"FTP server not covered by this check: {', '.join(others)}")
            return res
        return res.skip("No vsftpd server running")

    pid = names["vsftpd"]
    args = rem.run(f"tr '\\0' ' ' < /proc/{int(pid)}/cmdline", sudo=True).out.split()
    candidates = [a for a in args[1:] if a.endswith(".conf") and valid_path(a)] + list(CONF_PATHS)
    path, text = None, ""
    for c in candidates:
        r = rem.run(f"cat {shlex.quote(c)}", sudo=True)
        if r.rc == 0:
            path, text = c, r.out
            break
    conf = parse_conf(text)
    res.data["config"] = path or "(no file: built-in defaults)"

    writable = []
    root = conf.get("anon_root")
    if not root:   # without anon_root, anonymous users land in the ftp user's home directory
        fields = rem.run("getent passwd ftp").out.strip().split(":")
        root = fields[5] if len(fields) > 5 else ""
    res.data["anon_root"] = root or ""
    if root and valid_path(root):
        writable = rem.run(f"find {shlex.quote(root)} -maxdepth 3 -type d -perm -0002 2>/dev/null",
                           sudo=True).out.split()
    titles = " ".join(ctx.cache.get("nmap_titles", []))
    for sev, title, detail in evaluate(conf, writable, "Anonymous FTP" in titles):
        res.add(sev, title, detail)
    res.add("info", f"vsftpd: configuration read from {res.data['config']}")
    return res
