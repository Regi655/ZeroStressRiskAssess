"""Saved targets: a short name for a whole zsra command line.

    zsra save laptop 192.168.1.14 -u danielb -i ~/.ssh/riskassess_laptop --clamav-quick
    zsra laptop                       # = zsra 192.168.1.14 -u danielb -i ~/.ssh/riskassess_laptop --clamav-quick
    zsra laptop --skip clamav         # options added after the name are appended (and win, as on any command line)
    zsra targets                      # list
    zsra forget laptop

Stored in ~/.config/zsra/targets.json (mode 600: it holds addresses, user names and key paths, not secrets).
Passwords are never saved: they are asked when needed (cli.py). A name has no dots, so it can never be mistaken
for an IP address or a full host name; a saved name wins over a short host name with the same spelling, and zsra
says so.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,39}$")
# Options that would put a secret on disk, or that make no sense in a saved line.
REFUSED = {"--sudo-pass-env", "--yes", "--recover", "--out-dir"}
RESERVED = {"save", "targets", "forget", "web", "portal", "compare", "finalize", "inventory", "pdf", "help"}


class TargetError(Exception):
    pass


def path() -> Path:
    if os.environ.get("ZSRA_TARGETS"):
        return Path(os.environ["ZSRA_TARGETS"]).expanduser()
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "zsra" / "targets.json"


def load() -> dict:
    p = path()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        raise TargetError(f"{p}: unreadable ({exc})")
    return {k: v for k, v in data.items() if NAME.match(k) and isinstance(v, list)
            and all(isinstance(a, str) for a in v)} if isinstance(data, dict) else {}


def _write(data: dict):
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = p.with_name(p.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, p)


def save(name: str, argv: list) -> None:
    if not NAME.match(name) or name in RESERVED:
        raise TargetError(f"invalid name {name!r}: a letter, then letters, digits, - or _ (no dots), "
                          f"not one of: {', '.join(sorted(RESERVED))}")
    if not argv:
        raise TargetError("nothing to save: zsra save NAME HOST -u USER [options]")
    bad = [a for a in argv if a.split("=", 1)[0] in REFUSED]
    if bad:
        raise TargetError(f"not saved in a target: {', '.join(bad)} (add it when you run it)")
    data = load()
    data[name] = list(argv)
    _write(data)


def forget(name: str) -> bool:
    data = load()
    if name not in data:
        return False
    del data[name]
    _write(data)
    return True


def expand(argv: list):
    """(argv with a leading saved name replaced by its line, the name or None)."""
    if not argv or not NAME.match(argv[0]):
        return argv, None
    data = load()
    if argv[0] not in data:
        return argv, None
    return data[argv[0]] + list(argv[1:]), argv[0]
