# Lab machines for ZeroStressRiskAssess: Ubuntu 24.04 containers, one per PROFILE.
#   severe  deliberately severe misconfigurations   (expected risk: CRITICAL)
#   medium  neglected server, nothing critical      (expected: HIGH)
#   clean   stock install, fully updated            (expected: HIGH, because of SSH password login)
#   secure  hardened configuration                  (expected: LOW, i.e. it passes)
# All passwords and data are FAKE. The profile is selected with --build-arg PROFILE=... (set by compose).
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Common base layer: SSH and minimal utilities only. nmap, Lynis, ClamAV and Grype are NOT installed: they are
# handled by ZeroStressRiskAssess (ClamAV is installed and removed, Lynis is copied). APT lists are kept in the
# image because the update checks rely on them. This layer is identical for all profiles, so Docker builds
# it only once.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      openssh-server sudo passwd python3 ca-certificates iproute2 procps less \
 && ssh-keygen -A

# Changes on every `lab.sh up`: forces Docker to re-run the package upgrade of the updated profiles instead
# of reusing a cached layer that could be missing recent security updates.
ARG UPDATE_STAMP=none
ARG PROFILE=severe
COPY profiles/ /tmp/build/
COPY entrypoint.sh /usr/local/bin/lab-entrypoint.sh
RUN chmod +x /usr/local/bin/lab-entrypoint.sh \
 && echo "update stamp: $UPDATE_STAMP" \
 && LAB_BUILD=1 bash /tmp/build/"$PROFILE".sh \
 && echo "$PROFILE" > /etc/lab-profile \
 && rm -rf /tmp/build

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/lab-entrypoint.sh"]
