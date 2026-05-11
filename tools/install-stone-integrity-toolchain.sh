#!/usr/bin/env bash
set -euo pipefail

INSTALL_RUST="${INSTALL_RUST:-1}"
INSTALL_DOCKER="${INSTALL_DOCKER:-0}"
INSTALL_STONE="${INSTALL_STONE:-1}"
INSTALL_CAIRO1_RUN="${INSTALL_CAIRO1_RUN:-1}"
INSTALL_INTEGRITY="${INSTALL_INTEGRITY:-1}"

STONE_PROVER_DIR="${STONE_PROVER_DIR:-$HOME/stone-prover}"
CAIRO_VM_DIR="${CAIRO_VM_DIR:-$HOME/cairo-vm}"
INTEGRITY_DIR="${INTEGRITY_DIR:-$HOME/integrity}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
STONE_DOCKER_IMAGE="${STONE_DOCKER_IMAGE:-zkstark-amaci-stone-prover}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  tools/install-stone-integrity-toolchain.sh [options]

Installs the extra toolchain needed after local Scarb/Stwo proving:
  - Rust/cargo
  - Stone prover binaries: cpu_air_prover and cpu_air_verifier
  - cairo-vm/cairo1-run
  - Herodotus Integrity proof_serializer

Defaults:
  - install Rust with rustup when cargo is missing
  - build Stone prover through the official Dockerfile and copy binaries to BIN_DIR
  - build cairo1-run from lambdaclass/cairo-vm
  - build proof_serializer from HerodotusDev/integrity
  - do not install Docker automatically unless --install-docker is passed

Options:
  --install-docker       Install docker.io with apt if Docker is missing.
  --skip-rust           Do not install Rust/cargo.
  --skip-stone          Do not build Stone cpu_air_prover/cpu_air_verifier.
  --skip-cairo1-run     Do not build cairo-vm/cairo1-run.
  --skip-integrity      Do not build Integrity proof_serializer.
  --help                Show this help.

Environment overrides:
  BIN_DIR=~/.local/bin
  STONE_PROVER_DIR=~/stone-prover
  CAIRO_VM_DIR=~/cairo-vm
  INTEGRITY_DIR=~/integrity
  STONE_DOCKER_IMAGE=zkstark-amaci-stone-prover

Notes:
  - This targets Ubuntu 22.04/24.04 on Linux/amd64.
  - Stone's upstream build is Linux-only and the official path uses Docker.
  - The build can take a long time and requires substantial disk space.
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
    echo "This installer targets Linux/amd64. Current arch: $arch" >&2
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
    tar \
    make \
    cmake \
    clang \
    lld \
    libssl-dev \
    python3 \
    python3-pip
}

install_docker() {
  if has_command docker; then
    log "Docker already available"
    return
  fi

  log "Installing docker.io"
  sudo_cmd apt-get install -y docker.io
}

ensure_docker_running() {
  require_command docker

  if docker info >/dev/null 2>&1; then
    return
  fi

  log "Starting Docker service"
  if has_command systemctl; then
    sudo_cmd systemctl start docker || true
  fi
  if ! docker info >/dev/null 2>&1 && has_command service; then
    sudo_cmd service docker start || true
  fi

  if ! docker info >/dev/null 2>&1; then
    echo "Docker is installed but the daemon is not reachable." >&2
    echo "Start Docker, then rerun this script." >&2
    exit 1
  fi
}

install_rust() {
  export PATH="$HOME/.cargo/bin:$PATH"

  if has_command cargo; then
    log "Cargo already available: $(cargo --version)"
    return
  fi

  log "Installing Rust/cargo with rustup"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal
  export PATH="$HOME/.cargo/bin:$PATH"
}

ensure_bin_dir() {
  mkdir -p "$BIN_DIR"
  export PATH="$BIN_DIR:$HOME/.cargo/bin:$PATH"
}

clone_if_missing() {
  local url="$1"
  local dir="$2"

  if [[ -d "$dir/.git" ]]; then
    log "Using existing checkout: $dir"
    return
  fi

  log "Cloning $url"
  git clone "$url" "$dir"
}

install_stone_binaries() {
  if has_command cpu_air_prover && has_command cpu_air_verifier; then
    log "Stone prover binaries already available"
    return
  fi

  if [[ "$INSTALL_DOCKER" == "1" ]]; then
    install_docker
  fi

  ensure_docker_running
  clone_if_missing "https://github.com/starkware-libs/stone-prover.git" "$STONE_PROVER_DIR"

  log "Building Stone prover Docker image"
  (
    cd "$STONE_PROVER_DIR"
    docker build --tag "$STONE_DOCKER_IMAGE" .
  )

  log "Copying cpu_air_prover and cpu_air_verifier to $BIN_DIR"
  local container_id
  container_id="$(docker create "$STONE_DOCKER_IMAGE")"
  docker cp -L "$container_id:/bin/cpu_air_prover" "$BIN_DIR/cpu_air_prover"
  docker cp -L "$container_id:/bin/cpu_air_verifier" "$BIN_DIR/cpu_air_verifier"
  docker rm "$container_id" >/dev/null
  chmod +x "$BIN_DIR/cpu_air_prover" "$BIN_DIR/cpu_air_verifier"
}

install_cairo1_run() {
  if has_command cairo1-run; then
    log "cairo1-run already available"
    return
  fi

  require_command cargo
  clone_if_missing "https://github.com/lambdaclass/cairo-vm.git" "$CAIRO_VM_DIR"

  log "Building cairo-vm/cairo1-run"
  (
    cd "$CAIRO_VM_DIR/cairo1-run"
    make deps
    cargo build --release
  )

  local built_bin=""
  if [[ -x "$CAIRO_VM_DIR/target/release/cairo1-run" ]]; then
    built_bin="$CAIRO_VM_DIR/target/release/cairo1-run"
  elif [[ -x "$CAIRO_VM_DIR/cairo1-run/target/release/cairo1-run" ]]; then
    built_bin="$CAIRO_VM_DIR/cairo1-run/target/release/cairo1-run"
  fi

  if [[ -n "$built_bin" ]]; then
    ln -sf "$built_bin" "$BIN_DIR/cairo1-run"
    return
  fi

  log "Creating cairo1-run cargo wrapper"
  cat > "$BIN_DIR/cairo1-run" <<EOF
#!/usr/bin/env bash
exec cargo run --release --manifest-path "$CAIRO_VM_DIR/cairo1-run/Cargo.toml" -- "\$@"
EOF
  chmod +x "$BIN_DIR/cairo1-run"
}

install_integrity_serializer() {
  if has_command proof_serializer; then
    log "proof_serializer already available"
    return
  fi

  require_command cargo
  clone_if_missing "https://github.com/HerodotusDev/integrity.git" "$INTEGRITY_DIR"

  log "Building Integrity proof_serializer"
  (
    cd "$INTEGRITY_DIR"
    cargo build --release --bin proof_serializer
  )

  if [[ -x "$INTEGRITY_DIR/target/release/proof_serializer" ]]; then
    ln -sf "$INTEGRITY_DIR/target/release/proof_serializer" "$BIN_DIR/proof_serializer"
    return
  fi

  log "Creating proof_serializer cargo wrapper"
  cat > "$BIN_DIR/proof_serializer" <<EOF
#!/usr/bin/env bash
exec cargo run --release --manifest-path "$INTEGRITY_DIR/Cargo.toml" --bin proof_serializer -- "\$@"
EOF
  chmod +x "$BIN_DIR/proof_serializer"
}

persist_path_hint() {
  local line='export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"'
  if [[ -f "$HOME/.profile" ]] && grep -Fq "$line" "$HOME/.profile"; then
    return
  fi

  log "Adding PATH hint to ~/.profile"
  printf '\n# Added by zkStark-amaci Stone/Integrity toolchain installer\n%s\n' "$line" >> "$HOME/.profile"
}

verify_toolchain() {
  export PATH="$BIN_DIR:$HOME/.cargo/bin:$PATH"
  log "Checking Stone/Integrity toolchain"
  "$ROOT_DIR/tools/run-stone.sh" --check
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-docker)
      INSTALL_DOCKER=1
      shift
      ;;
    --skip-rust)
      INSTALL_RUST=0
      shift
      ;;
    --skip-stone)
      INSTALL_STONE=0
      shift
      ;;
    --skip-cairo1-run)
      INSTALL_CAIRO1_RUN=0
      shift
      ;;
    --skip-integrity)
      INSTALL_INTEGRITY=0
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
ensure_bin_dir

if [[ "$INSTALL_RUST" == "1" ]]; then
  install_rust
fi

if [[ "$INSTALL_STONE" == "1" ]]; then
  install_stone_binaries
fi

if [[ "$INSTALL_CAIRO1_RUN" == "1" ]]; then
  install_cairo1_run
fi

if [[ "$INSTALL_INTEGRITY" == "1" ]]; then
  install_integrity_serializer
fi

persist_path_hint
verify_toolchain

cat <<'EOF'

Stone/Integrity toolchain installation complete.

Next commands:
  npm run check:stone-toolchain

If tools are not found in a new shell, run:
  source ~/.profile
EOF
