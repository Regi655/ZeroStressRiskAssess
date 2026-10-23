#!/usr/bin/env bash
#
# setup.sh - prepares the controller (the machine that runs the assessments) for ZeroStressRiskAssess.
#
#   ./setup.sh            Python environment (.venv), dependencies, Lynis in vendor/lynis, external tool check
#   ./setup.sh --check    external tool check only
#
# Nothing is installed system-wide: for nmap, ssh-audit, Grype, Trivy and Docker the required command is printed.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

# pip 26.2.2: the first release that no longer trusts the compromised eMudhra/emSign intermediate CAs (October 2026:
# their private keys were exposed, so anyone could impersonate an HTTPS site to a client that trusts them, including
# PyPI to an older pip). pip installs packages over HTTPS with its own CA bundle, so an older pip is the weak link
# exactly while it downloads the new one. Bootstrap: the wheel is fetched by URL and checked against its SHA-256
# (from the Python security announcement): the hash protects the download even if the TLS connection did not.
# Source: https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576
PIP_MIN="26.2.2"
PIP_WHEEL="https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl"
PIP_SHA256="fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
# Ubuntu ca-certificates without emSign ECC Root CA - G3 (USN-8944-1): 20260816ubuntu0.XX.04.1
CA_MIN_DATE="20260816"

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
  if command -v trivy >/dev/null; then
    tv=$(trivy --version 2>/dev/null | awk '/^Version/ {print $2; exit}')
    # v0.69.4 is the malicious release of the March 2026 supply-chain attack (CVE-2026-33634).
    if [ "$tv" = "0.69.4" ]; then miss "trivy 0.69.4 is the COMPROMISED release (CVE-2026-33634): remove it (see README)"
    else ok "trivy $tv"; fi
  else miss "trivy (CVE, optional second source) -> see README, Requirements (Aqua's signed APT repository)"; fi
  command -v git >/dev/null && ok "git" || miss "git             -> sudo apt install git"
  if [ -x .venv/bin/python ]; then
    pv=$(.venv/bin/python -m pip --version 2>/dev/null | awk '{print $2}')
    if .venv/bin/python -c "import sys; v=tuple(int(x) for x in '${pv:-0}'.split('.')[:3]); sys.exit(v < (26, 2, 2))" 2>/dev/null
    then ok "pip $pv in .venv"
    else miss "pip ${pv:-?} in .venv trusts the compromised eMudhra CAs -> ./setup.sh (installs pip $PIP_MIN by hash)"; fi
  fi
  if command -v dpkg-query >/dev/null; then
    cv=$(dpkg-query -W -f='${Version}' ca-certificates 2>/dev/null || true)
    if [ -n "$cv" ] && [ "${cv%%[!0-9]*}" -lt "$CA_MIN_DATE" ] 2>/dev/null; then
      miss "ca-certificates $cv still trusts emSign (USN-8944-1) -> sudo apt update && sudo apt install --only-upgrade ca-certificates"
    elif [ -n "$cv" ]; then ok "ca-certificates $cv"; fi
  fi
  if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then ok "docker + compose (lab only)"
  else miss "docker (lab only) -> https://docs.docker.com/engine/install/ubuntu/"; fi
  [ -f vendor/lynis/lynis ] && ok "Lynis $(grep -m1 'PROGRAM_VERSION=' vendor/lynis/lynis | cut -d'"' -f2) in vendor/lynis" \
    || miss "Lynis           -> git clone --depth 1 https://github.com/CISOfy/lynis vendor/lynis"
}

if [ "${1:-}" != "--check" ]; then
  echo "==> Python environment (.venv)"
  python3 -m venv .venv
  # pip first, by hash (see PIP_WHEEL above), then everything else with the fixed pip.
  .venv/bin/python -m pip install --quiet "pip @ ${PIP_WHEEL}#sha256=${PIP_SHA256}"
  pv=$(.venv/bin/python -m pip --version | awk '{print $2}')
  .venv/bin/python -c "import sys; v=tuple(int(x) for x in '$pv'.split('.')[:3]); sys.exit(v < (26, 2, 2))" \
    || { echo "ERROR: pip $pv in .venv is older than $PIP_MIN (compromised eMudhra CAs): stopping before downloading anything else"; exit 1; }
  .venv/bin/python -m pip install --quiet --upgrade pip   # newer releases, if any, now downloaded with a safe pip
  .venv/bin/pip install --quiet -e '.[pdf]'   # [pdf] = ReportLab, for report.pdf
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
  echo "nmap, ssh-audit, Grype and Trivy are optional: without them those checks are skipped and the report says so."
else
  echo "All set. Activate the environment:  source .venv/bin/activate   then:  zsra --help"
fi
