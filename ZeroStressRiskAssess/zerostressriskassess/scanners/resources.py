"""Resource usage and temperatures (CPU, load, RAM, swap, disk space, sensors).

WHY it belongs in a risk assessment: a cryptominer or a botnet often shows up as CONSTANT high CPU and unusual
temperatures; a full disk or exhausted RAM are availability risks (services stop, logs are lost).

/proc and /sys are read directly: nothing is installed, and no program that malware could have replaced is trusted.

TEMPERATURE THRESHOLDS: there is no number right for everything (a desktop CPU, an NVMe disk and a Raspberry Pi
have very different limits). The kernel exposes the limits DECLARED by the component's manufacturer:
  - hwmon:   tempN_max (above it: "hot") and tempN_crit (above it the component shuts down or is damaged);
  - thermal: the zone's "trip points" (critical, hot, passive = where the CPU starts throttling).
When the sensor declares them they are used, and the report says where the threshold comes from; otherwise a
generic threshold is used, declared as such.

In a CONTAINER /proc/stat, the load and the sensors are those of the HOST machine (seen in the Rocky lab: "constant
CPU at 94%" was the laptop, not the target): the values are reported as information, not as risks of the target.
"""
from __future__ import annotations

from ..models import ScanResult

SAMPLES = 3   # CPU measurement intervals (1 second each)

SCRIPT = r"""
echo "NPROC|$(nproc 2>/dev/null)"
c=0; { [ -f /.dockerenv ] || [ -f /run/.containerenv ]; } && c=1; echo "CONTAINER|$c"
i=0
while [ $i -le @SAMPLES@ ]; do
  echo "STAT|$(head -1 /proc/stat 2>/dev/null)"
  [ $i -lt @SAMPLES@ ] && sleep 1
  i=$((i+1))
done
grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null | sed 's/^/MEM|/'
echo "LOAD|$(cat /proc/loadavg 2>/dev/null)"
echo "UPTIME|$(uptime -p 2>/dev/null)"
# Mount points that are FILES are skipped: in a container /etc/hosts, /etc/resolv.conf and /etc/hostname are
# bind mounts of the host's disk (seen in the Rocky lab report: "/etc/hosts 32%" was the host). The root "/" is
# always measured, also when it is an overlay (a container's root): it is the space the target writes to.
# efivarfs (/sys/firmware/efi/efivars) is the firmware's variable store, not a disk: 70% on the Ubuntu laptop.
{ df -P / 2>/dev/null; df -P -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null; } \
  | awk '$1 != "Filesystem" {print $6 "|" $5}' | while IFS='|' read -r m u; do [ -d "$m" ] && echo "DF|$m|$u"; done
findmnt -rno TARGET,OPTIONS 2>/dev/null | awk '$2 ~ /(^|,)ro(,|$)/ {print "RO|" $1}'
for f in /sys/class/hwmon/hwmon*/temp*_input; do
  [ -r "$f" ] || continue
  d=${f%/*}; b=${f%_input}
  echo "HWMON|$(cat $d/name 2>/dev/null)|$(cat ${b}_label 2>/dev/null)|$(cat $f 2>/dev/null)|$(cat ${b}_max 2>/dev/null)|$(cat ${b}_crit 2>/dev/null)"
done
for z in /sys/class/thermal/thermal_zone*; do
  [ -r "$z/temp" ] || continue
  trips=""
  for t in $z/trip_point_*_type; do
    [ -r "$t" ] || continue
    trips="$trips $(cat $t 2>/dev/null):$(cat ${t%_type}_temp 2>/dev/null)"
  done
  echo "TZ|$(cat $z/type 2>/dev/null)|$(cat $z/temp 2>/dev/null)|$trips"
done
true
"""

GENERIC_TEMP = (80, 90)        # (medium, high) °C: used ONLY if the sensor declares no limits
PLAUSIBLE_TEMP = (1, 150)      # outside this range the value is a sensor placeholder, not a measurement


def _int(s):
    s = (s or "").strip()
    return int(s) if s.lstrip("-").isdigit() else None


def _milli(s):
    """Sensors give thousandths of a degree ("45000" = 45 °C). Implausible values -> None."""
    v = _int(s)
    if v is None:
        return None
    c = v / 1000
    return c if PLAUSIBLE_TEMP[0] <= c <= PLAUSIBLE_TEMP[1] else None


def _cpu_pct(a: str, b: str):
    """Percentage of busy CPU between two readings of the 'cpu' line of /proc/stat."""
    try:
        va = [int(x) for x in a.split()[1:9]]
        vb = [int(x) for x in b.split()[1:9]]
    except (ValueError, IndexError):
        return None
    if len(va) < 5 or len(vb) < 5:
        return None
    idle = (vb[3] + vb[4]) - (va[3] + va[4])   # idle + iowait
    total = sum(vb) - sum(va)
    return round(100 * (1 - idle / total), 1) if total > 0 else None


def parse(text: str) -> dict:
    """SCRIPT output -> data. Pure function: every unreadable line is ignored."""
    d = {"stat": [], "mem": {}, "disks": [], "temps": [], "nproc": None, "loadavg": "", "uptime": "",
         "container": False, "ro": set()}
    for line in text.splitlines():
        tag, _, rest = line.partition("|")
        p = rest.split("|")
        if tag == "CONTAINER":
            d["container"] = rest.strip() == "1"
        elif tag == "NPROC":
            d["nproc"] = _int(rest)
        elif tag == "STAT" and rest.startswith("cpu "):
            d["stat"].append(rest)
        elif tag == "MEM" and ":" in rest:
            k, v = rest.split(":", 1)
            n = _int(v.split()[0] if v.split() else "")
            if n is not None:
                d["mem"][k.strip()] = n
        elif tag == "LOAD":
            d["loadavg"] = rest.strip()
        elif tag == "UPTIME":
            d["uptime"] = rest.strip()
        elif tag == "RO" and rest.strip():
            d["ro"].add(rest.strip())
        elif tag == "DF" and len(p) == 2 and p[1].rstrip("%").isdigit() and p[0] not in {x["mount"] for x in d["disks"]}:
            d["disks"].append({"mount": p[0], "use_pct": int(p[1].rstrip("%"))})
        elif tag == "HWMON" and len(p) == 5:
            c = _milli(p[2])
            if c is not None:
                name = p[0] + (f" ({p[1]})" if p[1] else "")
                d["temps"].append({"sensor": name or "?", "celsius": c, "max": _milli(p[3]),
                                   "crit": _milli(p[4]), "kind": "hwmon"})
        elif tag == "TZ" and len(p) >= 2:
            c = _milli(p[1])
            if c is None:
                continue
            trips = {}
            for item in (p[2] if len(p) > 2 else "").split():
                t, _, v = item.partition(":")
                v = _milli(v)
                if v is not None and (t not in trips or v < trips[t]):
                    trips[t] = v
            hot = [trips[k] for k in ("hot", "passive") if k in trips]
            d["temps"].append({"sensor": f"thermal zone {p[0] or '?'}", "celsius": c,
                               "max": min(hot) if hot else None, "crit": trips.get("critical"), "kind": "thermal"})
    # CPU over several intervals. The MINIMUM says whether the load is CONSTANT (a miner's is; a peak caused by
    # our own commands is not); the average gives the general idea.
    samples = [x for x in (_cpu_pct(a, b) for a, b in zip(d["stat"], d["stat"][1:])) if x is not None]
    d["cpu_samples"] = samples
    d["cpu_pct"] = round(sum(samples) / len(samples), 1) if samples else None
    d["cpu_sustained"] = min(samples) if samples else None
    m = d["mem"]
    d["ram_pct"] = (round(100 * (1 - m["MemAvailable"] / m["MemTotal"]), 1)
                    if m.get("MemTotal") and "MemAvailable" in m else None)
    d["swap_pct"] = round(100 * (1 - m.get("SwapFree", 0) / m["SwapTotal"]), 1) if m.get("SwapTotal") else 0.0
    return d


def temp_verdict(t: dict):
    """(severity, title, detail) for a sensor, or None if normal.
    Priority: declared critical limit > declared "hot" limit > generic threshold."""
    c, mx, cr, s = t["celsius"], t.get("max"), t.get("crit"), t["sensor"]
    if cr is not None:
        src = f"critical limit declared by the sensor: {cr:.0f}°C"
        if c >= cr:
            return "critical", f"Temperature {s}: {c:.0f}°C, above the critical limit", src
        if c >= cr - 5:
            return "high", f"Temperature {s}: {c:.0f}°C, less than 5°C from the critical limit", src
    if mx is not None:
        src = f"'hot' limit declared by the sensor: {mx:.0f}°C" + (f"; critical {cr:.0f}°C" if cr else "")
        if c >= mx:
            return ("medium" if cr else "high"), f"Temperature {s}: {c:.0f}°C, above the 'hot' limit", src
        if cr is None and c >= mx - 5:
            return "medium", f"Temperature {s}: {c:.0f}°C, close to the 'hot' limit", src
    if cr is None and mx is None:
        src = f"generic threshold {GENERIC_TEMP[0]}/{GENERIC_TEMP[1]}°C: the sensor declares no limits"
        if c >= GENERIC_TEMP[1]:
            return "high", f"Temperature {s}: {c:.0f}°C, very high", src
        if c >= GENERIC_TEMP[0]:
            return "medium", f"Temperature {s}: {c:.0f}°C, high", src
    return None


def evaluate(d: dict) -> list:
    """[(severity, title, detail)]. Pure function."""
    out = []

    def pct(value, name, med, high, detail=""):
        if value is None:
            return
        if value >= high:
            out.append(("high", f"{name} very high: {value}%", detail))
        elif value >= med:
            out.append(("medium", f"{name} high: {value}%", detail))

    if d["cpu_sustained"] is not None:
        pct(d["cpu_sustained"], "Constant CPU usage", 85, 95,
            f"minimum over {len(d['cpu_samples'])} 1-second measurements: {d['cpu_samples']} (an isolated peak "
            "does not count). Check the processes (top_cpu in report.json): a constant load nobody explains is "
            "a classic sign of a cryptominer.")
    # 5-minute load average divided by the cores: above 1 means processes queueing for the CPU.
    load = d["loadavg"].split()
    if d["nproc"] and len(load) >= 2:
        try:
            per_core = float(load[1]) / d["nproc"]
        except ValueError:
            per_core = None
        if per_core is not None and per_core >= 2:
            out.append(("high" if per_core >= 4 else "medium",
                        f"High load: {per_core:.1f} processes queueing per core (5-minute average)",
                        f"loadavg {d['loadavg']}, cores {d['nproc']}"))
    pct(d["ram_pct"], "RAM usage", 85, 95, "RAM that cannot be reclaimed (MemAvailable)")
    pct(d["swap_pct"], "Swap usage", 50, 80)
    # Read-only filesystems are skipped: an image mounted ro is full by construction and cannot fill up (seen on the
    # development sandbox: /opt/claude-code, ext4 ro, 92% used).
    for disk in (x for x in d["disks"] if x["mount"] not in d.get("ro", ())):
        pct(disk["use_pct"], f"Disk space used on {disk['mount']}", 80, 90,
            "A full filesystem stops services and logging (and with the logs, the evidence of an attack).")

    # The same sensor seen twice (e.g. acpitz in hwmon and as a thermal zone): once.
    seen = set()
    for t in sorted(d["temps"], key=lambda t: t["kind"] != "hwmon"):
        key = (t["sensor"].split(" (")[0].replace("thermal zone ", ""), t["celsius"])
        if key in seen:
            continue
        seen.add(key)
        v = temp_verdict(t)
        if v:
            out.append(v)
    return out


HOST_VALUES = ("Constant CPU", "High load", "RAM usage", "Swap usage", "Temperature")


def run(ctx) -> ScanResult:
    res, rem = ScanResult("resources"), ctx.rem
    d = parse(rem.run(SCRIPT.replace("@SAMPLES@", str(SAMPLES)), timeout=60).out)
    container = bool(ctx.cache.get("container")) or d["container"]
    for sev, title, detail in evaluate(d):
        if container and title.startswith(HOST_VALUES):
            sev, title = "info", f"[host machine] {title}"   # the host's value, not a risk of the target
        res.add(sev, title, detail)
    if container:
        res.add("info", "Target in a container: CPU, load, RAM and temperatures are those of the host machine",
                "Disk space of the container's root (/) and of its mounted directories is evaluated normally.")
    res.data = {
        "cpu_pct": d["cpu_pct"], "cpu_sustained": d["cpu_sustained"], "cpu_samples": d["cpu_samples"],
        "ram_pct": d["ram_pct"], "swap_pct": d["swap_pct"], "disks": d["disks"], "temps": d["temps"],
        "loadavg": d["loadavg"], "cpu_cores": d["nproc"], "uptime": d["uptime"], "container": container,
        "top_cpu": rem.run("ps -eo pid,user,%cpu,%mem,comm --sort=-%cpu | head -6").out,
    }
    if not d["temps"]:
        res.add("info", "No temperature sensor exposed (normal on VMs and containers)")
    missing = [n for n, v in (("CPU", d["cpu_pct"]), ("RAM", d["ram_pct"])) if v is None]
    if missing:
        res.add("info", "Measurements not available: " + ", ".join(missing), "/proc not readable or unexpected format")
    fmt = lambda v: "?" if v is None else f"{v}%"  # noqa: E731
    res.add("info", f"CPU {fmt(d['cpu_pct'])} | RAM {fmt(d['ram_pct'])} | swap {fmt(d['swap_pct'])} | "
                    f"load {d['loadavg'] or '?'}")
    return res
