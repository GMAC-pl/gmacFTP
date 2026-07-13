#!/usr/bin/env bash
# Measure gmacftp cold + warm start (requires hyperfine: `brew install hyperfine`).
# `sudo purge` flushes the disk cache between runs for an honest cold-start number.
set -euo pipefail

BIN="${1:-./target/release/gmacftp}"

if [[ ! -x "$BIN" ]]; then
  echo "Binary not found: $BIN — build first with: cargo build --release" >&2
  exit 1
fi

if ! command -v hyperfine >/dev/null 2>&1; then
  echo "hyperfine not installed. Install with: brew install hyperfine" >&2
  exit 1
fi

echo "== warm (cache hot, no purge) =="
hyperfine --warmup 3 --runs 10 "$BIN --bench"

echo
echo "== cold (sudo purge between each run) =="
sudo hyperfine --prepare 'sudo purge' --runs 20 "$BIN --bench"

echo
echo "== binary size =="
du -h "$BIN"
