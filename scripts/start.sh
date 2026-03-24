#!/usr/bin/env bash
# Start kntrl daemon
# Required env: KNTRL_MODE (default: monitor)
# Optional env: KNTRL_CUSTOM_RULES_FILE, KNTRL_CUSTOM_RULES_DIR, KNTRL_API_URL, KNTRL_API_KEY
set -euo pipefail

INPUT_MODE="${KNTRL_MODE:-monitor}"
INPUT_CUSTOM_RULES_FILE="${KNTRL_CUSTOM_RULES_FILE:-}"
INPUT_CUSTOM_RULES_DIR_PATH="${KNTRL_CUSTOM_RULES_DIR:-}"
INPUT_API_URL="${KNTRL_API_URL:-}"
INPUT_API_KEY="${KNTRL_API_KEY:-}"

RULES_DIR="/tmp/kntrl-rules"
REPORT_FILE="/tmp/kntrl-report.json"

KNTRL_ARGS=(
  start
  --mode "${INPUT_MODE}"
  --rules-dir "${RULES_DIR}"
  --output-file-name "${REPORT_FILE}"
)

# ── Custom rules file (merged by kntrl) ──
if [ -n "${INPUT_CUSTOM_RULES_FILE}" ] && [ -f "${INPUT_CUSTOM_RULES_FILE}" ]; then
  KNTRL_ARGS+=(--rules-file "${INPUT_CUSTOM_RULES_FILE}")
fi

# ── Custom rules directory (copy contents into rules dir) ──
if [ -n "${INPUT_CUSTOM_RULES_DIR_PATH}" ] && [ -d "${INPUT_CUSTOM_RULES_DIR_PATH}" ]; then
  cp -r "${INPUT_CUSTOM_RULES_DIR_PATH}"/* "${RULES_DIR}/" 2>/dev/null || true
fi

# ── Cloud configuration ──
if [ -n "${INPUT_API_URL}" ]; then
  export KNTRL_API_URL="${INPUT_API_URL}"
fi
if [ -n "${INPUT_API_KEY}" ]; then
  export KNTRL_API_KEY="${INPUT_API_KEY}"
fi

KNTRL_LOG="/tmp/kntrl-daemon.log"

echo "[kntrl] Starting kntrl agent"
echo "[kntrl] Command: sudo kntrl ${KNTRL_ARGS[*]}"
sudo -E nohup kntrl "${KNTRL_ARGS[@]}" > "${KNTRL_LOG}" 2>&1 &
KNTRL_PID=$!
echo "${KNTRL_PID}" | sudo tee /var/run/kntrl.pid > /dev/null

# Wait briefly for kntrl to attach eBPF probes
sleep 2

if kill -0 "${KNTRL_PID}" 2>/dev/null; then
  echo "[kntrl] Agent started (pid: ${KNTRL_PID})"
else
  echo "ERROR: kntrl agent failed to start. Log output:"
  cat "${KNTRL_LOG}" || true
  exit 1
fi
