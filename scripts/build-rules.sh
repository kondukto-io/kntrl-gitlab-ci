#!/usr/bin/env bash
# Build kntrl rules directory from environment variables
# Maps all KNTRL_* env vars to rules.yaml
set -euo pipefail

RULES_DIR="/tmp/kntrl-rules"
mkdir -p "${RULES_DIR}"
RULES_FILE="${RULES_DIR}/rules.yaml"

# Resolve the defaults directory relative to this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULTS_DIR="${SCRIPT_DIR}/../defaults"

# ── Defaults from env (with fallbacks) ──
INPUT_MODE="${KNTRL_MODE:-monitor}"
INPUT_ENABLE_DEFAULT_NETWORK="${KNTRL_ENABLE_DEFAULT_NETWORK_RULES:-true}"
INPUT_ENABLE_DEFAULT_PROCESS="${KNTRL_ENABLE_DEFAULT_PROCESS_RULES:-true}"
INPUT_ENABLE_DEFAULT_DNS="${KNTRL_ENABLE_DEFAULT_DNS_RULES:-true}"
INPUT_ENABLE_DEFAULT_FILE="${KNTRL_ENABLE_DEFAULT_FILE_RULES:-true}"
INPUT_ENABLE_DEFAULT_REGO="${KNTRL_ENABLE_DEFAULT_SUPPLY_CHAIN_REGO:-true}"
INPUT_ALLOWED_HOSTS="${KNTRL_ALLOWED_HOSTS:-}"
INPUT_ALLOWED_IPS="${KNTRL_ALLOWED_IPS:-}"
INPUT_ALLOW_LOCAL_RANGES="${KNTRL_ALLOW_LOCAL_RANGES:-true}"
INPUT_ALLOW_GITLAB_META="${KNTRL_ALLOW_GITLAB_META:-true}"
INPUT_ALLOW_METADATA="${KNTRL_ALLOW_METADATA:-false}"
INPUT_EXTRA_BLOCKED_EXECUTABLES="${KNTRL_EXTRA_BLOCKED_EXECUTABLES:-}"
INPUT_EXTRA_MONITORED_PATHS="${KNTRL_EXTRA_MONITORED_PATHS:-}"
INPUT_EXTRA_PROTECTED_PATHS="${KNTRL_EXTRA_PROTECTED_PATHS:-}"
INPUT_EXTRA_MONITORED_ENV_VARS="${KNTRL_EXTRA_MONITORED_ENV_VARS:-}"
INPUT_CUSTOM_REGO_FILE="${KNTRL_CUSTOM_REGO_FILE:-}"
INPUT_NETWORK_PROFILES="${KNTRL_NETWORK_PROFILES:-}"
INPUT_EXTRA_BLOCKED_CHAINS="${KNTRL_EXTRA_BLOCKED_CHAINS:-}"

# ── Helper: convert comma-separated string to YAML list items ──
csv_to_yaml() {
  local csv="$1" indent="$2"
  IFS=',' read -ra items <<< "${csv}"
  for item in "${items[@]}"; do
    item="$(echo "${item}" | xargs)"
    [ -n "${item}" ] && echo "${indent}- \"${item}\""
  done
}

# ══════════════════════════════════════════
# Generate rules.yaml
# ══════════════════════════════════════════
{
  echo 'version: "1"'
  echo "mode: ${INPUT_MODE}"
  echo "rules:"

  # ── Network section ──
  echo "  network:"

  if [ "${INPUT_ENABLE_DEFAULT_NETWORK}" = "true" ] || [ -n "${INPUT_ALLOWED_HOSTS}" ]; then
    echo "    allowed_hosts:"
    if [ "${INPUT_ENABLE_DEFAULT_NETWORK}" = "true" ]; then
      cat "${DEFAULTS_DIR}/network_hosts.txt"
    fi
    # Add GitLab-specific hosts
    echo '      - "gitlab.com"'
    echo '      - ".gitlab.com"'
    echo '      - ".gitlab-static.net"'
    echo '      - "registry.gitlab.com"'
    if [ -n "${INPUT_ALLOWED_HOSTS}" ]; then
      csv_to_yaml "${INPUT_ALLOWED_HOSTS}" "      "
    fi
  fi

  if [ "${INPUT_ENABLE_DEFAULT_NETWORK}" = "true" ] || [ -n "${INPUT_ALLOWED_IPS}" ]; then
    echo "    allowed_ips:"
    if [ "${INPUT_ENABLE_DEFAULT_NETWORK}" = "true" ]; then
      echo '      - "10.0.0.0/8"'
      echo '      - "172.16.0.0/12"'
      echo '      - "192.168.0.0/16"'
    fi
    if [ -n "${INPUT_ALLOWED_IPS}" ]; then
      csv_to_yaml "${INPUT_ALLOWED_IPS}" "      "
    fi
  fi

  echo "    allow_local_ranges: ${INPUT_ALLOW_LOCAL_RANGES}"
  echo "    allow_github_meta: false"
  echo "    allow_metadata: ${INPUT_ALLOW_METADATA}"

  # -- Network profiles --
  if [ "${INPUT_ENABLE_DEFAULT_NETWORK}" = "true" ] || [ -n "${INPUT_NETWORK_PROFILES}" ]; then
    echo "    profiles:"
    if [ "${INPUT_ENABLE_DEFAULT_NETWORK}" = "true" ]; then
      cat "${DEFAULTS_DIR}/network_profiles.txt"
    fi
    if [ -n "${INPUT_NETWORK_PROFILES}" ]; then
      python3 -c "
import json, sys
for p in json.loads(sys.argv[1]):
    print(f'      - process: \"{p[\"process\"]}\"')
    print('        allowed_hosts:')
    for h in p.get('allowed_hosts', []):
        print(f'          - \"{h}\"')
" "${INPUT_NETWORK_PROFILES}"
    fi
  fi

  # ── Process section ──
  if [ "${INPUT_ENABLE_DEFAULT_PROCESS}" = "true" ] || [ -n "${INPUT_EXTRA_BLOCKED_EXECUTABLES}" ] || [ -n "${INPUT_EXTRA_BLOCKED_CHAINS}" ]; then
    echo "  process:"
    echo "    enabled: true"

    # -- Blocked chains --
    if [ "${INPUT_ENABLE_DEFAULT_PROCESS}" = "true" ] || [ -n "${INPUT_EXTRA_BLOCKED_CHAINS}" ]; then
      echo "    blocked_chains:"
      if [ "${INPUT_ENABLE_DEFAULT_PROCESS}" = "true" ]; then
        cat "${DEFAULTS_DIR}/process_rules.txt"
      fi
      if [ -n "${INPUT_EXTRA_BLOCKED_CHAINS}" ]; then
        python3 -c "
import json, sys
for c in json.loads(sys.argv[1]):
    print(f'      - process: \"{c[\"process\"]}\"')
    ancestors = ', '.join(f'\"{a}\"' for a in c['ancestors'])
    print(f'        ancestors: [{ancestors}]')
" "${INPUT_EXTRA_BLOCKED_CHAINS}"
      fi
    fi

    # -- Blocked executables --
    echo "    blocked_executables:"
    if [ "${INPUT_ENABLE_DEFAULT_PROCESS}" = "true" ]; then
      echo '      - "nc"'
      echo '      - "ncat"'
      echo '      - "nmap"'
      echo '      - "socat"'
      echo '      - "trufflehog"'
    fi
    if [ -n "${INPUT_EXTRA_BLOCKED_EXECUTABLES}" ]; then
      csv_to_yaml "${INPUT_EXTRA_BLOCKED_EXECUTABLES}" "      "
    fi
  fi

  # ── DNS section ──
  if [ "${INPUT_ENABLE_DEFAULT_DNS}" = "true" ]; then
    echo "  dns:"
    echo "    allowed_servers:"
    echo '      - "8.8.8.8"'
    echo '      - "8.8.4.4"'
    echo '      - "1.1.1.1"'
    echo '      - "1.0.0.1"'
  fi

  # ── File section ──
  if [ "${INPUT_ENABLE_DEFAULT_FILE}" = "true" ] || \
     [ -n "${INPUT_EXTRA_MONITORED_PATHS}" ] || \
     [ -n "${INPUT_EXTRA_PROTECTED_PATHS}" ] || \
     [ -n "${INPUT_EXTRA_MONITORED_ENV_VARS}" ]; then
    echo "  file:"
    echo "    enabled: true"

    echo "    monitored_paths:"
    if [ "${INPUT_ENABLE_DEFAULT_FILE}" = "true" ]; then
      cat "${DEFAULTS_DIR}/file_monitored_paths.txt"
    fi
    if [ -n "${INPUT_EXTRA_MONITORED_PATHS}" ]; then
      csv_to_yaml "${INPUT_EXTRA_MONITORED_PATHS}" "      "
    fi

    echo "    protected_paths:"
    if [ "${INPUT_ENABLE_DEFAULT_FILE}" = "true" ]; then
      cat "${DEFAULTS_DIR}/file_protected_paths.txt"
    fi
    if [ -n "${INPUT_EXTRA_PROTECTED_PATHS}" ]; then
      csv_to_yaml "${INPUT_EXTRA_PROTECTED_PATHS}" "      "
    fi

    echo "    monitored_env_vars:"
    if [ "${INPUT_ENABLE_DEFAULT_FILE}" = "true" ]; then
      cat "${DEFAULTS_DIR}/file_env_vars.txt"
    fi
    if [ -n "${INPUT_EXTRA_MONITORED_ENV_VARS}" ]; then
      csv_to_yaml "${INPUT_EXTRA_MONITORED_ENV_VARS}" "      "
    fi
  fi

  echo "webhooks: []"

} > "${RULES_FILE}"

# ══════════════════════════════════════════
# Copy OPA rego files
# ══════════════════════════════════════════
if [ "${INPUT_ENABLE_DEFAULT_REGO}" = "true" ]; then
  cp "${DEFAULTS_DIR}/supply_chain.rego" "${RULES_DIR}/supply_chain.rego"
fi

if [ -n "${INPUT_CUSTOM_REGO_FILE}" ] && [ -f "${INPUT_CUSTOM_REGO_FILE}" ]; then
  cp "${INPUT_CUSTOM_REGO_FILE}" "${RULES_DIR}/$(basename "${INPUT_CUSTOM_REGO_FILE}")"
fi

echo "[kntrl] Generated rules:"
cat "${RULES_FILE}"
echo "---"
ls -la "${RULES_DIR}/"

# Export for subsequent scripts
echo "${RULES_DIR}"
