#!/usr/bin/env bash
#
# setup.sh - prepares the controller (the machine that runs the assessments) for ZeroStressRiskAssess.
#
#   ./setup.sh            Python environment (.venv), dependencies, Lynis in vendor/lynis, external tool check
#   ./setup.sh --check    external tool check only
#
# Nothing is installed system-wide: for nmap, ssh-audit, Grype and Docker the required command is printed.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

ok()   { printf '  [ok]      %s\n' "$*"; }
miss() { printf '  [missing] %s\n' "$*"; MISSING=1; }
MISSING=0

check_tools() {
  echo "External programs:"
  command -v python3 >/dev/null && ok "python3 $(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')" \
    || miss "python3 (sudo apt install python3 python3-venv)"
  python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>/dev/null || miss "Python 3.9 or later"
  command -v nmap >/dev/null && ok "nmap" || miss "nmap            -> sudo apt install nmap"
  command -v ssh-audit >/dev/null && ok "ssh-audit" || miss "ssh-audit       -> sudo apt install ssh-audit   (or: pipx install ssh-audit)"
  command -v grype >/dev/null && ok "grype $(grype version 2>/dev/null | awk '/^Version/ {print $2}')" \
    || miss "grype (CVE)     -> curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin"
  command -v git >/dev/null && ok "git" || miss "git             -> sudo apt install git"
  if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then ok "docker + compose (lab only)"
  else miss "docker (lab only) -> https://docs.docker.com/engine/install/ubuntu/"; fi
  [ -f vendor/lynis/lynis ] && ok "Lynis $(grep -m1 'PROGRAM_VERSION=' vendor/lynis/lynis | cut -d'"' -f2) in vendor/lynis" \
    || miss "Lynis           -> git clone --depth 1 https://github.com/CISOfy/lynis vendor/lynis"
}

if [ "${1:-}" != "--check" ]; then
  echo "==> Python environment (.venv)"
  python3 -m venv .venv
  .venv/bin/pip install --quiet --upgrade pip
  .venv/bin/pip install --quiet -e .
  echo "==> Lynis (copied to the target during the assessment, never installed)"
  if [ ! -f vendor/lynis/lynis ]; then
    git clone --quiet --depth 1 https://github.com/CISOfy/lynis vendor/lynis
  else
    git -C vendor/lynis pull --quiet --ff-only || echo "  (Lynis update failed: keeping the current version)"
  fi
  echo
fi
check_tools
echo
if [ "$MISSING" = 1 ]; then
  echo "Install what is missing (commands above), then: ./setup.sh --check"
  echo "nmap, ssh-audit and Grype are optional: without them those checks are skipped and the report says so."
else
  echo "All set. Activate the environment:  source .venv/bin/activate   then:  zsra --help"
fi
