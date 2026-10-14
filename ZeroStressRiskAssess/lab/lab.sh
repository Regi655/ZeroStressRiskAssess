#!/usr/bin/env bash
#
# lab.sh - four Ubuntu lab machines for testing ZeroStressRiskAssess (Docker).
#
#   ./lab/lab.sh up [PROFILE]          build and start (no profile: all four)
#   ./lab/lab.sh assess [PROFILE] ...  run ZeroStressRiskAssess against one profile (default: severe);
#                                      options after the profile are passed to the tool (e.g. --clamav-quick)
#   ./lab/lab.sh verify [...]          assess ALL profiles and compare with the expected risk
#   ./lab/lab.sh info [PROFILE]        contents of each profile and expected findings
#   ./lab/lab.sh status                container status
#   ./lab/lab.sh ssh [PROFILE]         SSH login as 'dev'
#   ./lab/lab.sh reset [PROFILE]       recreate from scratch (equivalent to reverting a snapshot)
#   ./lab/lab.sh down                  stop and remove all containers
#
# Profiles:  severe (expected CRITICAL)  medium (HIGH)  clean (HIGH)  secure (LOW = pass)
# Different network: LAB_PREFIX=10.99.0 ./lab/lab.sh up   (IPs .10 .11 .12 .13)

set -euo pipefail

LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$LAB")"
KEY="$LAB/.ssh/lab_key"
PREFIX="${LAB_PREFIX:-172.28.10}"
PROFILES=(severe medium clean secure)

# Per profile: last IP octet, expected overall risk, sudo password (FAKE, exists only inside the containers).
declare -A IPN=([severe]=10 [medium]=11 [clean]=12 [secure]=13)
declare -A EXPECTED=([severe]=CRITICAL [medium]=HIGH [clean]=HIGH [secure]=LOW)
declare -A SUDOPASS=([severe]="" [medium]="dev2020" [clean]="Clean-Lab-2026" [secure]="Secure-Lab-2026-q7")

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '\n==> %s\n' "$*"; }
# LAB_UPDATE changes on every "up" so that the updated profiles re-run "apt-get upgrade" (see Dockerfile)
# and always start with the latest security updates (about one extra minute per profile).
dc() { (cd "$LAB" && LAB_UPDATE="$(date +%s)" docker compose "$@"); }

profile() {   # validates the profile name (default: severe)
  local p="${1:-severe}"
  [[ -n "${IPN[$p]:-}" ]] || die "unknown profile: '$p' (valid: ${PROFILES[*]})"
  echo "$p"
}

check_docker() {
  command -v docker >/dev/null 2>&1 || die "Docker is not installed (see README, Requirements)."
  docker compose version >/dev/null 2>&1 || die "the 'docker compose' plugin is missing."
  docker info >/dev/null 2>&1 || die "the Docker daemon does not respond (is it running? is your user in the 'docker' group?)."
}

make_key() {
  # Lab-only key without passphrase: it never leaves this directory (.gitignore) and the user's personal
  # keys are never used.
  if [ ! -f "$KEY" ]; then
    log "Generating the lab SSH key ($KEY)"
    mkdir -p "$LAB/.ssh" && chmod 700 "$LAB/.ssh"
    ssh-keygen -q -t ed25519 -N '' -C 'zerostressriskassess-lab' -f "$KEY"
  fi
}

wait_ssh() {
  local c="zerostressriskassess-lab-$1"
  for _ in $(seq 1 30); do
    docker exec "$c" pgrep -x sshd >/dev/null 2>&1 && return 0
    sleep 1
  done
  die "sshd did not start in $c: docker logs $c"
}

forget_hostkey() {
  # Every new container has a new host key: the old entry is removed from known_hosts, otherwise SSH
  # (correctly) refuses the connection as a possible man-in-the-middle attack.
  ssh-keygen -R "$PREFIX.${IPN[$1]}" >/dev/null 2>&1 || true
}

which_profiles() { if [ -n "${1:-}" ]; then profile "$1"; else printf '%s\n' "${PROFILES[@]}"; fi; }

cmd_up() {
  check_docker; make_key
  local list; list=$(which_profiles "${1:-}")
  log "Starting: $(echo $list) (the first time the images are built: a few minutes)"
  # shellcheck disable=SC2086
  dc up -d --build $list
  for p in $list; do wait_ssh "$p"; forget_hostkey "$p"; done
  echo
  for p in $list; do printf '  %-7s %s   expected risk: %s\n' "$p" "$PREFIX.${IPN[$p]}" "${EXPECTED[$p]}"; done
  echo
  echo "Next step:  ./lab/lab.sh assess PROFILE    or    ./lab/lab.sh verify"
}

# Runs the tool against one profile; the report is written to reports/lab-PROFILE/.
run_assess() {
  local p="$1"; shift
  [ -f "$KEY" ] || die "lab key missing: run ./lab/lab.sh up first"
  local py="$ROOT/.venv/bin/python3"
  [ -x "$py" ] || py=python3
  local args=("$PREFIX.${IPN[$p]}" -u dev -i "$KEY" --accept-new-hostkey --yes --out-dir "$ROOT/reports/lab-$p")
  # --accept-new-hostkey: the container host key changes on every reset (see forget_hostkey).
  # The (fake) sudo password is passed through an environment variable of this command only, never as an
  # argument: command-line arguments are visible to every user through `ps`.
  if [ -n "${SUDOPASS[$p]}" ]; then
    (cd "$ROOT" && LAB_SUDO_PASS="${SUDOPASS[$p]}" "$py" -m zerostressriskassess "${args[@]}" --sudo-pass-env LAB_SUDO_PASS "$@")
  else
    (cd "$ROOT" && "$py" -m zerostressriskassess "${args[@]}" "$@")
  fi
}

result() {   # overall risk of the profile's latest report, plus the count per level
  local f; f=$(ls -1t "$ROOT"/reports/lab-"$1"/*/report.json 2>/dev/null | head -1)
  [ -n "$f" ] || { echo "-"; return; }
  python3 -c 'import json,sys; s=json.load(open(sys.argv[1]))["summary"]; print(s["level"], " ".join(f"{v}{k[0]}" for k,v in s["counts"].items()))' "$f"
}

cmd_assess() {
  local p="severe"
  if [ -n "${1:-}" ] && [[ "$1" != -* ]]; then p=$(profile "$1"); shift; fi
  run_assess "$p" "$@"
  local got; got=$(result "$p")
  echo
  if [ "${got%% *}" = "${EXPECTED[$p]}" ]; then echo "Profile $p: risk ${got%% *}, as expected."
  else echo "Profile $p: risk ${got%% *}, expected ${EXPECTED[$p]}."; fi
}

cmd_verify() {
  # Lab acceptance test: every profile must produce its expected overall risk.
  # Extra options (e.g. --clamav-quick, --skip clamav) are passed to the tool for every profile.
  local ok=0 tot=0 rows=()
  for p in "${PROFILES[@]}"; do
    log "Profile $p ($PREFIX.${IPN[$p]}), expected ${EXPECTED[$p]}"
    run_assess "$p" --no-banner "$@" || true   # one banner per profile would only clutter the log
    local got; got=$(result "$p")
    tot=$((tot + 1))
    if [ "${got%% *}" = "${EXPECTED[$p]}" ]; then ok=$((ok + 1)); rows+=("$(printf '  %-7s expected %-9s got %-24s OK' "$p" "${EXPECTED[$p]}" "$got")")
    else rows+=("$(printf '  %-7s expected %-9s got %-24s DIFFERENT' "$p" "${EXPECTED[$p]}" "$got")"); fi
  done
  echo; echo "Result (counts: C=critical H=high M=medium L=low):"
  printf '%s\n' "${rows[@]}"
  echo; echo "$ok of $tot profiles as expected. Reports in reports/lab-PROFILE/."
  [ "$ok" = "$tot" ]
}

cmd_status() {
  check_docker
  docker ps -a --filter "name=^zerostressriskassess-lab-" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
}

cmd_ssh() { local p; p=$(profile "${1:-}"); exec ssh -i "$KEY" -o StrictHostKeyChecking=accept-new "dev@$PREFIX.${IPN[$p]}"; }

cmd_reset() {
  check_docker; make_key
  local list; list=$(which_profiles "${1:-}")
  log "Recreating from scratch: $(echo $list)"
  # shellcheck disable=SC2086
  dc rm -sf $list >/dev/null
  # shellcheck disable=SC2086
  dc up -d --force-recreate $list
  for p in $list; do wait_ssh "$p"; forget_hostkey "$p"; done
  echo "Clean again: $(echo $list)"
}

cmd_down() { check_docker; dc down --remove-orphans; }

cmd_info() {
  local p="${1:-}"
  [ -z "$p" ] || p=$(profile "$p")
  if [ -z "$p" ] || [ "$p" = severe ]; then cat <<'EOF'
SEVERE (172.28.10.10, expected CRITICAL) - deliberately severe misconfigurations
  Accounts     guest without password; dev and dev2 share a UID; root with a weak password
  SSH          PermitRootLogin yes, passwords and empty passwords accepted, MaxAuthTries 10, X11
  sudo         dev without password (Defaults:dev !authenticate)
  FTP          anonymous with uploads to /srv/ftp/upload and /srv/ftp/pub (777)
  Permissions  /opt/app 777 with a world-writable db.env; dev's private key 644; /home/dev2 777
  Updates      image packages NOT updated
  ClamAV       two EICAR test files (harmless)
  Credentials (FAKE): dev/dev2020  dev2/welcome1  root/Passw0rd  guest/(empty)

EOF
  fi
  if [ -z "$p" ] || [ "$p" = medium ]; then cat <<'EOF'
MEDIUM (172.28.10.11, expected HIGH) - updated server, configured in a hurry
  FTP          for system users, unencrypted, no chroot, no firewall in front
  SSH          password login, MaxAuthTries 10, X11Forwarding
  sudo         one script without password (/usr/local/bin/restart-app)
  Permissions  /srv/app/upload writable by everyone, no sticky bit
  Updates      automatic updates disabled
  Credentials (FAKE): dev/dev2020 (sudo group)

EOF
  fi
  if [ -z "$p" ] || [ "$p" = clean ]; then cat <<'EOF'
CLEAN  (172.28.10.12, expected HIGH) - freshly installed and updated Ubuntu Server, no changes
  The defaults remain: SSH accepts passwords, X11Forwarding, no firewall.
  Shows that "freshly installed" does not mean "secure".
  Credentials (FAKE): dev/Clean-Lab-2026 (sudo group)

EOF
  fi
  if [ -z "$p" ] || [ "$p" = secure ]; then cat <<'EOF'
SECURE (172.28.10.13, expected LOW = pass) - hardened configuration
  Key-only SSH, no root login, modern algorithms, MaxAuthTries 3; nftables firewall (only SSH allowed in);
  sudo with password and logging; updates and automatic updates; banner; password ageing.
  Only improvement suggestions remain (LOW).
  Credentials (FAKE): dev/Secure-Lab-2026-q7 (sudo only: SSH accepts keys only)

EOF
  fi
}

case "${1:-}" in
  up) shift; cmd_up "${1:-}" ;;
  assess) shift; cmd_assess "$@" ;;
  verify) shift; cmd_verify "$@" ;;
  status) cmd_status ;;
  ssh) shift; cmd_ssh "${1:-}" ;;
  reset) shift; cmd_reset "${1:-}" ;;
  down) cmd_down ;;
  info) shift; cmd_info "${1:-}" ;;
  *) sed -n '3,17p' "${BASH_SOURCE[0]}"; exit 1 ;;
esac
