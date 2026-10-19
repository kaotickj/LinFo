#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo "Run: sudo ./scripts/install-helper.sh" >&2
  exit 1
fi
BASE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
# Install in a root-owned, non-user-writable path. Never execute project-tree code with pkexec.
install -d -o root -g root -m 0755 /usr/local/libexec
install -d -o root -g root -m 0755 /etc/sysctl.d
install -d -o root -g root -m 0700 /var/lib/linfo
install -d -o root -g root -m 0700 /var/lib/linfo/changes
install -o root -g root -m 0755 "$BASE/privileged/linfo-helper" /usr/local/libexec/linfo-helper
echo 'Installed trusted helper at /usr/local/libexec/linfo-helper'
echo 'Run LinFo GUI as your normal user. pkexec will request authentication for each transaction.'
