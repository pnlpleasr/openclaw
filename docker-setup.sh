#!/usr/bin/env bash
# docker-setup.sh — One-time setup for running the OpenClaw gateway in Docker.
#
# What it does (in order):
#   1. Detects host UID/GID for container user matching (warns if root)
#   2. Loads secrets from ~/.openclaw/.env if it exists (robust parser)
#   3. Generates a 256-bit gateway token if not already set
#   4. Validates and creates mount paths (config, workspace, vault)
#   5. Writes all env vars to the project .env (chmod 600, gitignored)
#   6. Builds the gateway Docker image
#   7. Runs the onboarding wizard interactively
#   8. Starts the gateway via Docker Compose
#
# Prerequisites:
#   - Docker and Docker Compose installed
#   - Must be run with bash (uses BASH_SOURCE; `bash docker-setup.sh` or `source docker-setup.sh`)
#
# Optional env vars (set before running):
#   OPENCLAW_VAULT_DIR    — Path to Obsidian vault (defaults to ~/.openclaw/workspace/vault)
#   OPENCLAW_EXTRA_MOUNTS — Comma-separated extra bind mounts (source:target[:opts])
#   OPENCLAW_UID/GID      — Override container user (defaults to host user's id)
#
# See docker-setup-guide.md for full documentation.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$ROOT_DIR/docker-compose.yml"
EXTRA_COMPOSE_FILE="$ROOT_DIR/docker-compose.extra.yml"
IMAGE_NAME="${OPENCLAW_IMAGE:-openclaw:local}"
EXTRA_MOUNTS="${OPENCLAW_EXTRA_MOUNTS:-}"
HOME_VOLUME_NAME="${OPENCLAW_HOME_VOLUME:-}"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing dependency: $1" >&2
    exit 1
  fi
}

contains_disallowed_chars() {
  local value="$1"
  [[ "$value" == *$'\n'* || "$value" == *$'\r'* || "$value" == *$'\t'* ]]
}

validate_mount_path_value() {
  local label="$1"
  local value="$2"
  local allow_spaces="${3:-false}"
  if [[ -z "$value" ]]; then
    fail "$label cannot be empty."
  fi
  if contains_disallowed_chars "$value"; then
    fail "$label contains unsupported control characters."
  fi
  # Paths used in short-form Docker volume syntax (source:target) cannot contain
  # spaces. The vault dir uses long-form bind syntax and may contain spaces
  # (e.g., iCloud's "Mobile Documents" path).
  if [[ "$allow_spaces" != "true" && "$value" =~ [[:space:]] ]]; then
    fail "$label cannot contain whitespace."
  fi
}

validate_named_volume() {
  local value="$1"
  if [[ ! "$value" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
    fail "OPENCLAW_HOME_VOLUME must match [A-Za-z0-9][A-Za-z0-9_.-]* when using a named volume."
  fi
}

validate_mount_spec() {
  local mount="$1"
  if contains_disallowed_chars "$mount"; then
    fail "OPENCLAW_EXTRA_MOUNTS entries cannot contain control characters."
  fi
  # Keep mount specs strict to avoid YAML structure injection.
  # Expected format: source:target[:options]
  if [[ ! "$mount" =~ ^[^[:space:],:]+:[^[:space:],:]+(:[^[:space:],:]+)?$ ]]; then
    fail "Invalid mount format '$mount'. Expected source:target[:options] without spaces."
  fi
}

require_cmd docker
if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose not available (try: docker compose version)" >&2
  exit 1
fi

OPENCLAW_CONFIG_DIR="${OPENCLAW_CONFIG_DIR:-$HOME/.openclaw}"
OPENCLAW_WORKSPACE_DIR="${OPENCLAW_WORKSPACE_DIR:-$HOME/.openclaw/workspace}"

validate_mount_path_value "OPENCLAW_CONFIG_DIR" "$OPENCLAW_CONFIG_DIR"
validate_mount_path_value "OPENCLAW_WORKSPACE_DIR" "$OPENCLAW_WORKSPACE_DIR"
if [[ -n "$HOME_VOLUME_NAME" ]]; then
  if [[ "$HOME_VOLUME_NAME" == *"/"* ]]; then
    validate_mount_path_value "OPENCLAW_HOME_VOLUME" "$HOME_VOLUME_NAME"
  else
    validate_named_volume "$HOME_VOLUME_NAME"
  fi
fi
if contains_disallowed_chars "$EXTRA_MOUNTS"; then
  fail "OPENCLAW_EXTRA_MOUNTS cannot contain control characters."
fi

mkdir -p "$OPENCLAW_CONFIG_DIR"
mkdir -p "$OPENCLAW_WORKSPACE_DIR"

# ── Environment setup ──────────────────────────────────────────────────────────

export OPENCLAW_CONFIG_DIR
export OPENCLAW_WORKSPACE_DIR
export OPENCLAW_GATEWAY_PORT="${OPENCLAW_GATEWAY_PORT:-18789}"
export OPENCLAW_BRIDGE_PORT="${OPENCLAW_BRIDGE_PORT:-18790}"
export OPENCLAW_GATEWAY_BIND="${OPENCLAW_GATEWAY_BIND:-lan}"

# Match the container's runtime UID/GID to the host user so bind-mounted
# directories (owned by the host user) are accessible inside the container.
# On macOS the default user is UID 501; on Linux it's typically 1000.
export OPENCLAW_UID="${OPENCLAW_UID:-$(id -u)}"
export OPENCLAW_GID="${OPENCLAW_GID:-$(id -g)}"
if [[ "$OPENCLAW_UID" == "0" ]]; then
  echo "WARNING: Running as root (UID 0). The container will run as root," >&2
  echo "which weakens security hardening. Consider setting OPENCLAW_UID=1000" >&2
  echo "and OPENCLAW_GID=1000 to run as a non-root user." >&2
fi
export OPENCLAW_IMAGE="$IMAGE_NAME"
export OPENCLAW_DOCKER_APT_PACKAGES="${OPENCLAW_DOCKER_APT_PACKAGES:-}"
export OPENCLAW_EXTRA_MOUNTS="$EXTRA_MOUNTS"
export OPENCLAW_HOME_VOLUME="$HOME_VOLUME_NAME"
# Vault directory for Obsidian or other knowledge base files.
# Defaults to workspace/vault if not set. For iCloud-synced Obsidian vaults:
#   export OPENCLAW_VAULT_DIR="/Users/<user>/Library/Mobile Documents/iCloud~md~obsidian/Documents/<vault>"
export OPENCLAW_VAULT_DIR="${OPENCLAW_VAULT_DIR:-${OPENCLAW_WORKSPACE_DIR}/vault}"
if [[ -n "$OPENCLAW_VAULT_DIR" ]]; then
  validate_mount_path_value "OPENCLAW_VAULT_DIR" "$OPENCLAW_VAULT_DIR" true
  mkdir -p "$OPENCLAW_VAULT_DIR"
fi

# Load secrets from ~/.openclaw/.env if they aren't already set.
# This file is created manually (see setup guide) and contains credentials
# that openclaw.json references via ${VAR} substitution.
_OPENCLAW_DOTENV="${OPENCLAW_CONFIG_DIR}/.env"
if [[ -f "$_OPENCLAW_DOTENV" ]]; then
  while IFS= read -r _line || [[ -n "$_line" ]]; do
    # Strip leading/trailing whitespace
    _line="${_line#"${_line%%[![:space:]]*}"}"
    _line="${_line%"${_line##*[![:space:]]}"}"
    # Skip blank lines and comments
    [[ -z "$_line" || "$_line" == \#* ]] && continue
    # Strip optional 'export ' prefix
    _line="${_line#export }"
    # Require KEY=VALUE format
    if [[ "$_line" != *=* ]]; then
      echo "WARNING: $_OPENCLAW_DOTENV: malformed line (no '=' found), skipping: $_line" >&2
      continue
    fi
    _key="${_line%%=*}"
    _val="${_line#*=}"
    # Validate key is a legal env var name
    if [[ ! "$_key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      echo "WARNING: $_OPENCLAW_DOTENV: invalid key name '$_key', skipping" >&2
      continue
    fi
    # Strip surrounding quotes from value
    if [[ "$_val" =~ ^\"(.*)\"$ ]]; then
      _val="${BASH_REMATCH[1]}"
    elif [[ "$_val" =~ ^\'(.*)\'$ ]]; then
      _val="${BASH_REMATCH[1]}"
    elif [[ "$_val" == \"* || "$_val" == \'* ]]; then
      echo "WARNING: $_OPENCLAW_DOTENV: value for '$_key' has unmatched quotes, using raw value" >&2
    fi
    # Only set if not already in the environment
    if [[ -z "${!_key:-}" ]]; then
      export "$_key=$_val"
    fi
  done < "$_OPENCLAW_DOTENV"
fi

# ── Gateway token ──────────────────────────────────────────────────────────────
# Generate a 256-bit hex token for gateway authentication if not already set.
# This token is required for all API calls to the gateway.

if [[ -z "${OPENCLAW_GATEWAY_TOKEN:-}" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    OPENCLAW_GATEWAY_TOKEN="$(openssl rand -hex 32)"
  else
    OPENCLAW_GATEWAY_TOKEN="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"
  fi
fi
export OPENCLAW_GATEWAY_TOKEN

# ── Compose file assembly ──────────────────────────────────────────────────────
# The base docker-compose.yml is always used. If extra mounts or a named home
# volume are configured, a docker-compose.extra.yml overlay is generated.

COMPOSE_FILES=("$COMPOSE_FILE")
COMPOSE_ARGS=()

write_extra_compose() {
  local home_volume="$1"
  shift
  local mount
  local gateway_home_mount
  local gateway_config_mount
  local gateway_workspace_mount

  cat >"$EXTRA_COMPOSE_FILE" <<'YAML'
services:
  openclaw-gateway:
    volumes:
YAML

  if [[ -n "$home_volume" ]]; then
    gateway_home_mount="${home_volume}:/home/node"
    gateway_config_mount="${OPENCLAW_CONFIG_DIR}:/home/node/.openclaw"
    gateway_workspace_mount="${OPENCLAW_WORKSPACE_DIR}:/home/node/.openclaw/workspace"
    validate_mount_spec "$gateway_home_mount"
    validate_mount_spec "$gateway_config_mount"
    validate_mount_spec "$gateway_workspace_mount"
    printf '      - %s\n' "$gateway_home_mount" >>"$EXTRA_COMPOSE_FILE"
    printf '      - %s\n' "$gateway_config_mount" >>"$EXTRA_COMPOSE_FILE"
    printf '      - %s\n' "$gateway_workspace_mount" >>"$EXTRA_COMPOSE_FILE"
  fi

  for mount in "$@"; do
    validate_mount_spec "$mount"
    printf '      - %s\n' "$mount" >>"$EXTRA_COMPOSE_FILE"
  done

  cat >>"$EXTRA_COMPOSE_FILE" <<'YAML'
  openclaw-cli:
    volumes:
YAML

  if [[ -n "$home_volume" ]]; then
    printf '      - %s\n' "$gateway_home_mount" >>"$EXTRA_COMPOSE_FILE"
    printf '      - %s\n' "$gateway_config_mount" >>"$EXTRA_COMPOSE_FILE"
    printf '      - %s\n' "$gateway_workspace_mount" >>"$EXTRA_COMPOSE_FILE"
  fi

  for mount in "$@"; do
    validate_mount_spec "$mount"
    printf '      - %s\n' "$mount" >>"$EXTRA_COMPOSE_FILE"
  done

  if [[ -n "$home_volume" && "$home_volume" != *"/"* ]]; then
    validate_named_volume "$home_volume"
    cat >>"$EXTRA_COMPOSE_FILE" <<YAML
volumes:
  ${home_volume}:
YAML
  fi
}

VALID_MOUNTS=()
if [[ -n "$EXTRA_MOUNTS" ]]; then
  IFS=',' read -r -a mounts <<<"$EXTRA_MOUNTS"
  for mount in "${mounts[@]}"; do
    mount="${mount#"${mount%%[![:space:]]*}"}"
    mount="${mount%"${mount##*[![:space:]]}"}"
    if [[ -n "$mount" ]]; then
      VALID_MOUNTS+=("$mount")
    fi
  done
fi

if [[ -n "$HOME_VOLUME_NAME" || ${#VALID_MOUNTS[@]} -gt 0 ]]; then
  # Bash 3.2 + nounset treats "${array[@]}" on an empty array as unbound.
  if [[ ${#VALID_MOUNTS[@]} -gt 0 ]]; then
    write_extra_compose "$HOME_VOLUME_NAME" "${VALID_MOUNTS[@]}"
  else
    write_extra_compose "$HOME_VOLUME_NAME"
  fi
  COMPOSE_FILES+=("$EXTRA_COMPOSE_FILE")
fi
for compose_file in "${COMPOSE_FILES[@]}"; do
  COMPOSE_ARGS+=("-f" "$compose_file")
done
COMPOSE_HINT="docker compose"
for compose_file in "${COMPOSE_FILES[@]}"; do
  COMPOSE_HINT+=" -f ${compose_file}"
done

# ── Project .env persistence ───────────────────────────────────────────────────
# Write all env vars to the project-level .env file that Docker Compose reads.
# This file is gitignored and chmod 600 (contains secrets).
# upsert_env preserves existing entries and updates/adds new ones.

ENV_FILE="$ROOT_DIR/.env"
upsert_env() {
  local file="$1"
  shift
  local -a keys=("$@")
  local tmp
  tmp="$(mktemp)"
  chmod 600 "$tmp"
  trap "rm -f '$tmp'" EXIT
  # Use a delimited string instead of an associative array so the script
  # works with Bash 3.2 (macOS default) which lacks `declare -A`.
  local seen=" "

  if [[ -f "$file" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      local key="${line%%=*}"
      local replaced=false
      for k in "${keys[@]}"; do
        if [[ "$key" == "$k" ]]; then
          printf '%s=%s\n' "$k" "${!k-}" >>"$tmp"
          seen="$seen$k "
          replaced=true
          break
        fi
      done
      if [[ "$replaced" == false ]]; then
        printf '%s\n' "$line" >>"$tmp"
      fi
    done <"$file"
  fi

  for k in "${keys[@]}"; do
    if [[ "$seen" != *" $k "* ]]; then
      printf '%s=%s\n' "$k" "${!k-}" >>"$tmp"
    fi
  done

  mv "$tmp" "$file"
  trap - EXIT
}

# Ensure the .env file exists before upsert_env replaces it.
# Permissions are set on the temp file inside upsert_env (chmod 600 before
# writing secrets), so the final file inherits 0600 via mv.
if [[ ! -f "$ENV_FILE" ]]; then
  touch "$ENV_FILE"
fi

upsert_env "$ENV_FILE" \
  OPENCLAW_CONFIG_DIR \
  OPENCLAW_WORKSPACE_DIR \
  OPENCLAW_GATEWAY_PORT \
  OPENCLAW_BRIDGE_PORT \
  OPENCLAW_GATEWAY_BIND \
  OPENCLAW_GATEWAY_TOKEN \
  OPENCLAW_IMAGE \
  OPENCLAW_EXTRA_MOUNTS \
  OPENCLAW_HOME_VOLUME \
  OPENCLAW_DOCKER_APT_PACKAGES \
  OPENCLAW_VAULT_DIR \
  OPENCLAW_UID \
  OPENCLAW_GID \
  TELEGRAM_BOT_TOKEN \
  GOOGLE_PLACES_API_KEY \
  NOTION_API_KEY \
  OPENAI_WHISPER_API_KEY

echo "==> Building Docker image: $IMAGE_NAME"
docker build \
  --build-arg "OPENCLAW_DOCKER_APT_PACKAGES=${OPENCLAW_DOCKER_APT_PACKAGES}" \
  -t "$IMAGE_NAME" \
  -f "$ROOT_DIR/Dockerfile" \
  "$ROOT_DIR"

echo ""
echo "==> Onboarding (interactive)"
echo "When prompted:"
echo "  - Gateway bind: lan"
echo "  - Gateway auth: token"
echo "  - Gateway token: (stored in $ENV_FILE)"
echo "  - Tailscale exposure: Off"
echo "  - Install Gateway daemon: No"
echo ""
docker compose "${COMPOSE_ARGS[@]}" run --rm openclaw-cli onboard --no-install-daemon

echo ""
echo "==> Provider setup (optional)"
echo "WhatsApp (QR):"
echo "  ${COMPOSE_HINT} run --rm openclaw-cli channels login"
echo "Telegram (bot token):"
echo "  ${COMPOSE_HINT} run --rm openclaw-cli channels add --channel telegram --token <token>"
echo "Discord (bot token):"
echo "  ${COMPOSE_HINT} run --rm openclaw-cli channels add --channel discord --token <token>"
echo "Docs: https://docs.openclaw.ai/channels"

echo ""
echo "==> Starting gateway"
docker compose "${COMPOSE_ARGS[@]}" up -d openclaw-gateway

echo ""
echo "Gateway running with host port mapping."
echo "Access from tailnet devices via the host's tailnet IP."
echo "Config: $OPENCLAW_CONFIG_DIR"
echo "Workspace: $OPENCLAW_WORKSPACE_DIR"
echo "Token: (stored in $ENV_FILE)"
echo ""
echo "Commands:"
echo "  ${COMPOSE_HINT} logs -f openclaw-gateway"
echo "  ${COMPOSE_HINT} exec openclaw-gateway node dist/index.js health --token \"\$OPENCLAW_GATEWAY_TOKEN\""
