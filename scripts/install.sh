#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RAW_BASE_DEFAULT="https://raw.githubusercontent.com/Karib0u/kernagent/main/scripts"
RAW_BASE="${KERNAGENT_SCRIPTS_BASE:-$RAW_BASE_DEFAULT}"

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
TAG="latest"
YES=0
QUIET=0
NO_COLOR_FLAG=0
VERBOSE=0
DOCKER_BIN="${DOCKER_BIN:-docker}"
PULLED_IMAGE=""

CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
CONFIG_DIR="${CONFIG_HOME}/kernagent"
VERSION_FILE="${CONFIG_DIR}/.version"

C_RED=""; C_GRN=""; C_YLW=""; C_BLU=""; C_RST=""

usage(){
  cat <<'USAGE'
Usage: install.sh [--prefix DIR] [--tag TAG] [--yes] [--quiet] [--no-color] [--verbose] [--docker-bin CMD]
USAGE
}

configure_colors(){
  if [[ -t 1 && "$NO_COLOR_FLAG" -eq 0 ]]; then
    C_RED=$'\033[31m'
    C_GRN=$'\033[32m'
    C_YLW=$'\033[33m'
    C_BLU=$'\033[34m'
    C_RST=$'\033[0m'
  fi
}

log(){ [[ "$QUIET" -eq 1 ]] && return 0; echo "${C_BLU}[*]${C_RST} $*"; }
ok(){ [[ "$QUIET" -eq 1 ]] && return 0; echo "${C_GRN}[✓]${C_RST} $*"; }
warn(){ echo "${C_YLW}[!]${C_RST} $*" >&2; }
die(){ echo "${C_RED}[x]${C_RST} $*" >&2; exit 1; }
run(){ if [[ "$VERBOSE" -eq 1 ]]; then echo "+ $*" >&2; fi; "$@"; }

need_cmd(){ command -v "$1" >/dev/null 2>&1 || die "Required command '$1' not found"; }

fetch_asset(){
  local name="$1"
  local target="$2"
  if [[ -f "${SCRIPT_DIR}/${name}" ]]; then
    cp "${SCRIPT_DIR}/${name}" "$target"
    return 0
  fi
  local url="${RAW_BASE%/}/${name}"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$target" || die "Failed to download ${name}"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$target" "$url" || die "Failed to download ${name}"
  else
    die "Need curl or wget to download ${name}"
  fi
}

ensure_dir(){
  local dir="$1"
  if [[ -d "$dir" ]]; then return 0; fi
  if mkdir -p "$dir" 2>/dev/null; then
    return 0
  fi
  run sudo mkdir -p "$dir"
}

move_file(){
  local src="$1" dest="$2"
  local dest_dir
  dest_dir="$(dirname "$dest")"
  ensure_dir "$dest_dir"
  if [[ -w "$dest_dir" && (! -e "$dest" || -w "$dest") ]]; then
    mv "$src" "$dest"
  else
    run sudo mv "$src" "$dest"
  fi
}

parse_args(){
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --prefix)
        [[ $# -lt 2 ]] && { usage >&2; exit 2; }
        INSTALL_DIR="$2"
        PREFIX_ARG="$2"
        shift 2
        ;;
      --prefix=*)
        INSTALL_DIR="${1#*=}"
        PREFIX_ARG="${1#*=}"
        shift
        ;;
      --tag)
        [[ $# -lt 2 ]] && { usage >&2; exit 2; }
        TAG="$2"
        shift 2
        ;;
      --tag=*)
        TAG="${1#*=}"
        shift
        ;;
      --yes)
        YES=1
        shift
        ;;
      --quiet)
        QUIET=1
        shift
        ;;
      --no-color)
        NO_COLOR_FLAG=1
        shift
        ;;
      --verbose)
        VERBOSE=1
        shift
        ;;
      --docker-bin)
        [[ $# -lt 2 ]] && { usage >&2; exit 2; }
        DOCKER_BIN="$2"
        shift 2
        ;;
      --docker-bin=*)
        DOCKER_BIN="${1#*=}"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        warn "Unknown argument: $1"
        usage >&2
        exit 2
        ;;
    esac
  done
}

check_docker(){
  need_cmd "$DOCKER_BIN"
  if ! "$DOCKER_BIN" info >/dev/null 2>&1; then
    die "${DOCKER_BIN} daemon not reachable. Is it running?"
  fi
}

pull_image(){
  local image="$1" repo tag alt pulled=""
  repo="${image%:*}"
  tag="${image##*:}"
  log "Pulling ${image}"
  if docker_pull "$image"; then
    pulled="$image"
  elif [[ "$tag" == v* ]]; then
    alt="${repo}:${tag#v}"
    warn "Image ${image} not found; retrying ${alt}"
    if docker_pull "$alt"; then
      pulled="$alt"
    fi
  fi
  if [[ -z "$pulled" ]]; then
    die "Failed to pull ${image}"
  fi
  PULLED_IMAGE="$pulled"
  ok "Image ready"
}

docker_pull(){
  if [[ "$VERBOSE" -eq 1 ]]; then
    echo "+ $DOCKER_BIN pull $1" >&2
  fi
  "$DOCKER_BIN" pull "$1"
}

template_wrapper(){
  local image="$1"
  local source tmp patched
  source="$(mktemp)"
  fetch_asset "kernagent" "$source"
  patched="$(mktemp)"
  sed "s|@@IMAGE_FQN@@|${image}|g" "$source" > "$patched"
  rm -f "$source"
  chmod +x "$patched"
  echo "$patched"
}

install_host_script(){
  local name="$1"
  local target="$2"
  local tmp
  tmp="$(mktemp)"
  fetch_asset "$name" "$tmp"
  chmod +x "$tmp"
  move_file "$tmp" "$target"
  ok "Installed $(basename "$target")"
}

write_version(){
  mkdir -p "$CONFIG_DIR"
  if ! printf '%s\n' "$TAG" > "$VERSION_FILE" 2>/dev/null; then
    warn "Could not write ${VERSION_FILE}";
    return 1
  fi
}

main(){
  parse_args "$@"
  configure_colors
  check_docker
  local image="ghcr.io/karib0u/kernagent:${TAG}"
  pull_image "$image"
  image="${PULLED_IMAGE:-$image}"
  local wrapper_tmp
  wrapper_tmp="$(template_wrapper "$image")"
  install_host_script "kernagent-update" "${INSTALL_DIR%/}/kernagent-update"
  install_host_script "kernagent-uninstall" "${INSTALL_DIR%/}/kernagent-uninstall"
  move_file "$wrapper_tmp" "${INSTALL_DIR%/}/kernagent"
  ok "Installed kernagent wrapper into ${INSTALL_DIR%/}"
  write_version || true
  if [[ ":$PATH:" != *":${INSTALL_DIR%/}:"* ]]; then
    warn "${INSTALL_DIR%/} not on PATH. Add it to use kernagent."
  fi
  log "Next: run 'kernagent init' to configure your LLM provider"
}

main "$@"
