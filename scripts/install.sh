#!/usr/bin/env bash
# Install kntrl binary
# Required env: KNTRL_VERSION (default: v0.1.15)
set -euo pipefail

VERSION="${KNTRL_VERSION:-v0.1.15}"
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
echo "[kntrl] Installed: $(kntrl --version 2>&1 || true)"
