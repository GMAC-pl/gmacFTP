#!/usr/bin/env bash
# Repeatable local performance suite for large listings, small files, recursive metadata and SFTP.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUNS="${GMACFTP_BENCH_RUNS:-3}"

cd "$ROOT"

echo "gmacFTP performance benchmark"
echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "host: $(uname -a)"
echo "rust: $(rustc --version)"
echo "runs per scenario: $RUNS"
echo

# Compile outside the timed region. Every following cargo invocation is then only a small launcher
# around the optimized test process; on macOS `/usr/bin/time -l` also reports peak resident memory.
cargo test --release --all-targets --no-run

run_scenario() {
  local filter="$1"
  local run
  echo
  echo "== $filter =="
  for ((run = 1; run <= RUNS; run++)); do
    echo "-- run $run / $RUNS --"
    if [[ "$(uname -s)" == "Darwin" ]]; then
      /usr/bin/time -l cargo test --release "$filter" -- --ignored --nocapture --test-threads=1
    else
      /usr/bin/time -v cargo test --release "$filter" -- --ignored --nocapture --test-threads=1
    fi
  done
}

run_scenario benchmark_virtualized_models_10k_and_50k_rows
run_scenario benchmark_many_small_transactional_file_copies
run_scenario benchmark_recursive_local_metadata
run_scenario benchmark_high_latency_sftp_upload

echo
echo "Cold/warm application start is measured separately: scripts/bench-cold-start.sh"
