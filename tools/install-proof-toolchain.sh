#!/usr/bin/env bash
set -euo pipefail

SCARB_VERSION="${SCARB_VERSION:-2.18.0}"
NODE_MAJOR="${NODE_MAJOR:-20}"
INSTALL_NODE="${INSTALL_NODE:-1}"
INSTALL_SCARB="${INSTALL_SCARB:-1}"
RUN_NPM_INSTALL="${RUN_NPM_INSTALL:-1}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  tools/install-proof-toolchain.sh [options]

Installs the CLI toolchain needed to run the local AMACI Cairo/STARK proof flow
on a high-performance Linux/amd64 machine.

Default installs/checks:
  - apt base tools: git, curl, ca-certificates, build-essential, pkg-config, unzip, tar
  - Node.js 20 and npm
  - Scarb/Cairo 2.18.0
  - npm dependencies for this repository

Options:
  --skip-node         Do not install Node.js/npm.
  --skip-scarb        Do not install Scarb/Cairo.
  --skip-npm-install  Do not run npm install in this repository.
  --help              Show this help.

Environment overrides:
  NODE_MAJOR=22       Install a different Node.js major version.
  SCARB_VERSION=2.18.0 Install a different Scarb version.

Notes:
  - This script targets Ubuntu 22.04/24.04 on amd64.
  - It uses sudo for apt package installation when needed.
  - It installs Scarb through the official Scarb installer.
EOF
}

log() {
  printf '\n==> %s\n' "$1"
}

has_command() {
  command -v "$1" >/dev/null 2>&1
}

require_command() {
  if ! has_command "$1"; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

version_major() {
  "$1" --version | sed -E 's/^v?([0-9]+).*/\1/'
}

ensure_linux_amd64() {
  local os
  local arch
  os="$(uname -s)"
  arch="$(uname -m)"

  if [[ "$os" != "Linux" ]]; then
    echo "This installer targets Linux. Current OS: $os" >&2
    exit 1
  fi

  if [[ "$arch" != "x86_64" && "$arch" != "amd64" ]]; then
    echo "This proof setup is intended for Linux/amd64. Current arch: $arch" >&2
    exit 1
  fi
}

ensure_apt() {
  if ! has_command apt-get; then
    echo "This installer currently supports apt-based Ubuntu/Debian systems." >&2
    exit 1
  fi
}

sudo_cmd() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$@"
  else
    require_command sudo
    sudo "$@"
  fi
}

install_base_packages() {
  log "Installing base apt packages"
  sudo_cmd apt-get update
  sudo_cmd apt-get install -y \
    ca-certificates \
    curl \
    git \
    build-essential \
    pkg-config \
    unzip \
    tar
}

install_node() {
  if has_command node && [[ "$(version_major node)" -ge "$NODE_MAJOR" ]] && has_command npm; then
    log "Node.js $(node --version) and npm $(npm --version) already available"
    return
  fi

  log "Installing Node.js ${NODE_MAJOR}.x"
  curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | sudo_cmd bash -
  sudo_cmd apt-get install -y nodejs
}

install_scarb() {
  export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

  if has_command scarb && scarb --version | head -n 1 | grep -q "scarb ${SCARB_VERSION}"; then
    log "Scarb ${SCARB_VERSION} already available"
    return
  fi

  log "Installing Scarb/Cairo ${SCARB_VERSION}"
  curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh \
    | sh -s -- -v "$SCARB_VERSION"

  export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
}

persist_path_hint() {
  local line='export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"'
  if [[ -f "$HOME/.profile" ]] && grep -Fq "$line" "$HOME/.profile"; then
    return
  fi

  log "Adding Scarb PATH hint to ~/.profile"
  printf '\n# Added by zkStark-amaci proof toolchain installer\n%s\n' "$line" >> "$HOME/.profile"
}

install_repo_dependencies() {
  log "Installing repository npm dependencies"
  if [[ -f "$ROOT_DIR/package-lock.json" ]]; then
    (cd "$ROOT_DIR" && npm ci)
  else
    (cd "$ROOT_DIR" && npm install)
  fi
}

verify_toolchain() {
  export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

  log "Verifying CLI tools"
  require_command git
  require_command curl
  require_command node
  require_command npm
  require_command scarb

  node_major="$(version_major node)"
  if [[ "$node_major" -lt 20 ]]; then
    echo "Node.js 20+ is required. Found: $(node --version)" >&2
    exit 1
  fi

  if ! scarb --version | head -n 1 | grep -q "scarb ${SCARB_VERSION}"; then
    echo "Expected Scarb ${SCARB_VERSION}, found:" >&2
    scarb --version >&2
    exit 1
  fi

  scarb execute --help >/dev/null
  scarb prove --help >/dev/null
  scarb verify --help >/dev/null

  printf '\n'
  git --version
  node --version
  npm --version
  scarb --version
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-node)
      INSTALL_NODE=0
      shift
      ;;
    --skip-scarb)
      INSTALL_SCARB=0
      shift
      ;;
    --skip-npm-install)
      RUN_NPM_INSTALL=0
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

ensure_linux_amd64
ensure_apt
install_base_packages

if [[ "$INSTALL_NODE" == "1" ]]; then
  install_node
fi

if [[ "$INSTALL_SCARB" == "1" ]]; then
  install_scarb
  persist_path_hint
fi

if [[ "$RUN_NPM_INSTALL" == "1" ]]; then
  install_repo_dependencies
fi

verify_toolchain

cat <<'EOF'

Toolchain installation complete.

Next commands:
  npm test
  npm run test:cairo-execute
  npm run prove:all-split-small

If scarb is not found in a new shell, run:
  source ~/.profile
EOF
