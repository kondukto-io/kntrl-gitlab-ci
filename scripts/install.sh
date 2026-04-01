#!/usr/bin/env bash
# Install kntrl binary with SHA256 verification
# Required env: KNTRL_VERSION (default: v0.2.1)
set -euo pipefail

VERSION="${KNTRL_VERSION:-v0.2.1}"
ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64)  ARCH_SUFFIX="amd64" ;;
  aarch64) ARCH_SUFFIX="arm64" ;;
  *)       echo "ERROR: Unsupported architecture: ${ARCH}"; exit 1 ;;
esac

if [ "${VERSION}" = "latest" ]; then
  DOWNLOAD_URL="https://github.com/kondukto-io/kntrl/releases/latest/download/kntrl.${ARCH_SUFFIX}"
else
  DOWNLOAD_URL="https://github.com/kondukto-io/kntrl/releases/download/${VERSION}/kntrl.${ARCH_SUFFIX}"
fi

echo "[kntrl] Installing kntrl (${VERSION}, ${ARCH_SUFFIX})"
sudo curl -fsSL -o /usr/local/bin/kntrl "${DOWNLOAD_URL}"
sudo chmod +x /usr/local/bin/kntrl

# ── SHA256 checksum verification ──
# Pinned checksums for known releases (matches kntrl-action/src/lib/checksums.ts)
declare -A CHECKSUMS
CHECKSUMS["v0.2.1:amd64"]="899b1eb6f8f86f139c7ba9648238b254255faddfb05e9e6c381586c396eac7f5"

CHECKSUM_KEY="${VERSION}:${ARCH_SUFFIX}"
if [ -n "${CHECKSUMS[${CHECKSUM_KEY}]:-}" ]; then
  EXPECTED="${CHECKSUMS[${CHECKSUM_KEY}]}"
  ACTUAL="$(sha256sum /usr/local/bin/kntrl | awk '{print $1}')"
  if [ "${ACTUAL}" != "${EXPECTED}" ]; then
    echo "ERROR: SHA256 checksum mismatch for kntrl ${VERSION} (${ARCH_SUFFIX})"
    echo "  Expected: ${EXPECTED}"
    echo "  Got:      ${ACTUAL}"
    sudo rm -f /usr/local/bin/kntrl
    exit 1
  fi
  echo "[kntrl] SHA256 checksum verified"
else
  echo "[kntrl] WARNING: No pinned checksum for ${VERSION}/${ARCH_SUFFIX} — skipping verification"
fi

echo "[kntrl] Installed: $(kntrl --version 2>&1 || true)"
