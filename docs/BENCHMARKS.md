# Performance benchmarks

The benchmark suite is intentionally built from the same production code paths as gmacFTP. It
does not need a real server and never reads saved connections or credentials.

## Run the suite

```sh
./scripts/bench-performance.sh
```

The script first compiles optimized test binaries outside the timed region, then runs every
scenario three times. Each result prints its workload, elapsed time and throughput. On macOS,
`/usr/bin/time -l` also prints `maximum resident set size` in bytes for peak-memory comparison.
Keep the Mac on AC power, close high-load applications, and compare medians from the same machine.

The scenarios cover:

- construction and repeated viewport reads of 10,000- and 50,000-row virtualized file models;
- transactional copying of 1,000 small files, including safe staging and finalization;
- bounded recursive metadata scanning of 10,000 files;
- an integrity-checked SFTP upload with 40 ms of injected latency per server request, exercising
  adaptive chunk/window tuning.

Workloads and repetitions can be changed without editing tracked files:

```sh
GMACFTP_BENCH_RUNS=5 \
GMACFTP_BENCH_SMALL_FILES=5000 \
GMACFTP_BENCH_METADATA_FILES=50000 \
GMACFTP_BENCH_SFTP_MIB=16 \
GMACFTP_BENCH_SFTP_LATENCY_MS=80 \
./scripts/bench-performance.sh
```

Safety bounds cap the configurable workloads at 20,000 small files, 100,000 metadata files,
256 MiB for the SFTP payload, and 1,000 ms injected latency. Temporary trees are created below the
system temporary directory and removed after each successful run.

## Cold and warm start

Build the optimized binary and run the dedicated harness:

```sh
cargo build --release
./scripts/bench-cold-start.sh
```

This requires `hyperfine`. Warm runs leave the filesystem cache intact. Cold runs invoke macOS
`purge` between samples and therefore ask for administrator authorization; they also affect the
system-wide disk cache, so do not run them while other latency-sensitive work is active. Benchmark
mode uses in-memory demo data, does not open the credential vault, and exits after controller/UI
construction.

## Regression checks

The ordinary test suite separately verifies properties that timings alone cannot establish:

- SFTP listing cancellation stops before all server pages are read and closes the directory
  handle;
- local listing cancellation stops after its current bounded batch;
- pipelined and resumed transfers preserve byte-for-byte integrity;
- adaptive SFTP tuning never exceeds its chunk or in-flight request bounds.

Record the git revision, macOS version, hardware, Rust version, workload variables, median time,
throughput and peak resident memory when publishing benchmark results. A performance change should
not be accepted if it improves time by weakening an integrity assertion or a safety bound.
