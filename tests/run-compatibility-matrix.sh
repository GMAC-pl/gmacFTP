#!/usr/bin/env bash
# Run destructive protocol round trips only against disposable localhost containers.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
REAL_CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
REAL_RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"

command -v docker >/dev/null || { echo "ERROR: Docker is required" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "ERROR: Docker daemon is not running" >&2; exit 1; }

IMAGE_PREFIX="gmacftp-compat"
CONTAINER=""
TMP="$(mktemp -d)"
cleanup() {
  if [ -n "$CONTAINER" ]; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

wait_for_port() {
  local port="$1"
  local attempt
  for attempt in $(seq 1 60); do
    if python3 - "$port" <<'PY'
import socket, sys
try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.2):
        pass
except OSError:
    raise SystemExit(1)
PY
    then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

run_case() {
  local server="$1"
  local protocol="$2"
  local host_port="$3"
  local container_port="$4"
  local image="$IMAGE_PREFIX-$server:local"
  if [ "$server" = "pure-ftpd" ]; then
    docker build --pull --file tests/compat/Dockerfile.pure-ftpd -t "$image" tests/compat
  else
    docker build --pull --build-arg "SERVER=$server" -t "$image" tests/compat
  fi
  CONTAINER="gmacftp-compat-$server-$$"
  local publish=(--publish "$host_port:$container_port")
  if [ "$protocol" = "ftp" ]; then
    publish+=(--publish 30000-30009:30000-30009)
  fi
  docker run --detach --name "$CONTAINER" "${publish[@]}" "$image" "$server" >/dev/null
  if ! wait_for_port "$host_port"; then
    docker logs "$CONTAINER" >&2 || true
    return 1
  fi

  echo "==> $server ($protocol)"
  XDG_CONFIG_HOME="$TMP/config-$server" \
  HOME="$TMP/home-$server" \
  CARGO_HOME="$REAL_CARGO_HOME" \
  RUSTUP_HOME="$REAL_RUSTUP_HOME" \
  GMACFTP_COMPAT_SERVER="$server" \
  GMACFTP_COMPAT_PROTOCOL="$protocol" \
  GMACFTP_COMPAT_PORT="$host_port" \
    cargo test --test protocol_compat protocol_server_round_trip -- --exact --nocapture --test-threads=1

  docker rm -f "$CONTAINER" >/dev/null
  CONTAINER=""
}

if [ "$#" -eq 0 ]; then
  servers=(openssh vsftpd proftpd pure-ftpd)
else
  servers=("$@")
fi

for server in "${servers[@]}"; do
  case "$server" in
    openssh) run_case openssh sftp 2222 2222 ;;
    vsftpd) run_case vsftpd ftp 2210 2121 ;;
    proftpd) run_case proftpd ftp 2210 2121 ;;
    pure-ftpd) run_case pure-ftpd ftp 2210 2121 ;;
    *) echo "ERROR: unknown server: $server" >&2; exit 64 ;;
  esac
done

echo "==> compatibility matrix passed"
