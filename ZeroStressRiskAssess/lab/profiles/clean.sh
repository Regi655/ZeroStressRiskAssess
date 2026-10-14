#!/usr/bin/env bash
#
# CLEAN profile - executed ONCE while building the image (NEVER on the host).
#
# Equivalent to a freshly installed and updated Ubuntu Server, WITHOUT any security change:
#   - packages updated and automatic updates enabled (as configured by the Ubuntu installer);
#   - an administrator 'dev' in the sudo group, with a password (as created by the installer);
#   - default Ubuntu SSH configuration: password login allowed, X11Forwarding enabled;
#   - no firewall (ufw installed but inactive, as after installation).
# Shows that "freshly installed" does not mean "secure". Expected risk: HIGH
# (SSH password login reachable from the network).
# FAKE credentials: dev / Clean-Lab-2026

set -euo pipefail
[ "${LAB_BUILD:-}" = 1 ] || { echo "This script must run ONLY while building the lab container image." >&2; exit 1; }

# The package lists of the base layer may be stale (Docker reuses it from cache): refresh them.
apt-get update
apt-get upgrade -y
apt-get install -y --no-install-recommends unattended-upgrades ufw
# Same file written by the Ubuntu Server installer: daily automatic security updates.
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'CONF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
CONF

useradd -m -s /bin/bash -G sudo dev
echo 'dev:Clean-Lab-2026' | chpasswd
