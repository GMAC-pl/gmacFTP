# Protocol compatibility and fault matrix

This matrix separates deterministic regression coverage from disposable-server interoperability
tests. No test uses a saved or production server. Run the server matrix with:

```sh
bash tests/run-compatibility-matrix.sh
```

The script builds one local image per server implementation, starts one server at a time, uses an
isolated HOME and configuration directory, performs
list/create/upload/rename/download/content-verify/delete, and removes every container and local
fixture afterward. The server fixtures never read saved gmacFTP connections or credentials.

## Server matrix

| Server | Tested version | Protocol path | Automated exercise | Result |
| --- | --- | --- | --- | --- |
| OpenSSH | 9.2p1 (`1:9.2p1-2+deb12u10`) | SFTP, password, explicit first-use host-key trust | `tests/protocol_compat.rs` | pass |
| vsftpd | `3.0.3-13+b2` | FTP, explicit per-connection plaintext exception | `tests/protocol_compat.rs` | pass |
| ProFTPD | `1.3.8+dfsg-4+deb12u5` | FTP, explicit per-connection plaintext exception | `tests/protocol_compat.rs` | pass |
| Pure-FTPd | 1.0.53, upstream source | FTP, explicit per-connection plaintext exception | `tests/protocol_compat.rs` | pass |

The complete matrix passed on 2026-07-13 on Apple Silicon using Docker 29.4 through OrbStack. The
Debian base manifest is pinned by digest. Pure-FTPd is built from its pinned 1.0.53 source archive
and verified against SHA-256
`2b2a80047f49a97b6924521fcb27978ad34ce55482b3e57b919cfd22436d2762`; it is configured without
Linux capabilities because the disposable container deliberately has a restricted capability set.
Pure-FTPd still uses its normal privilege-separation implementation and a dedicated unprivileged
`ftp` account.

## macOS architectures

The public distribution is a universal macOS binary containing both `arm64` and `x86_64`, with a
minimum deployment target of macOS 11. Earlier public builds served only Apple Silicon, which
excluded otherwise supported Intel Macs. No repository issue established a measurable volume of
Intel demand, but the native Rust/Slint stack cross-compiles cleanly and the ongoing cost of testing
the second target is small, so broad compatibility is the safer product decision.

On 2026-07-13, `cargo check --all-targets --target x86_64-apple-darwin` passed from an Apple Silicon
host with Rust 1.93.1 and Xcode 26.3. CI compiles release binaries for both Apple targets. The app
bundle script joins them with `lipo`, rejects missing or unexpected architectures, and performs this
verification before code signing. Personal/local builds remain native by default to avoid doubling
development build time; `MACKFTP_PERSONAL_ARCHS` can opt them into the universal build.

Plain FTP remains disabled by default. These fixtures deliberately enable it only for an isolated
localhost connection. Explicit/implicit FTPS, certificate pinning, changed-certificate rejection,
and client certificates are covered in the FTP unit suite without weakening production defaults.

## Fault matrix

| Fault | Required behavior | Regression evidence |
| --- | --- | --- |
| Slow or stalled FTP peer | bounded listing and transfer operations return an error; UI remains responsive | `listing_line_reader_has_an_absolute_deadline`, socket read/write deadlines |
| Slow or stalled SFTP peer | each request has a deadline; adaptive pipeline remains bounded | `benchmark_high_latency_sftp_upload`, `sftp_tuning_grows_latency_window_with_strict_bounds` |
| Network loss/reset | transient work may retry with bounded backoff; partial destination is never promoted | `retries_transient_transport_errors_only`, failed FTP/SFTP upload tests |
| Changed SFTP host key | fail closed and never replace the stored pin automatically | `host_key_mismatch_fails_closed_and_cannot_replace_pin` |
| New/changed FTPS certificate | require trust-once or endpoint pin; a changed pin warns and fails closed | `certificate_pins_are_canonical_and_detect_leaf_changes` |
| Local disk full/short write | keep the previous destination and remove the private staging file | `transactional_local_copy_preserves_destination_on_partial_write_failure` |
| Remote finalization failure | restore the previous destination and remove/preserve only the documented stage | FTP/SFTP failed-promotion tests |
| Permission/read error in a batch | report the failed file and let the user skip it or stop that batch | `skip_failed_file_allows_the_next_batch_job_to_run`, `stop_marks_remaining_batch_jobs_as_skipped` |
| Cancellation | do not expose a partial completed file and do not block later queue entries | cancelled FTP/SFTP and transfer scheduler tests |

## Zakres po polsku

Macierz uruchamia wyłącznie jednorazowe serwery na `localhost`. Sprawdza pełny obieg pliku na
OpenSSH, vsftpd, ProFTPD i Pure-FTPd, a osobne testy wymuszają zerwanie sieci, timeout, zmianę
klucza/certyfikatu, brak miejsca, odmowę uprawnień i anulowanie. Zwykły FTP nadal jest domyślnie
wyłączony; wyjątek istnieje tylko w konfiguracji konkretnego serwera testowego. Pełna macierz
zakończyła się powodzeniem 2026-07-13, bez użycia zapisanych serwerów ani danych logowania
użytkownika.

Publiczna aplikacja jest budowana jako jeden uniwersalny plik dla Apple Silicon i Intela
(`arm64 + x86_64`, macOS 11+). Obie architektury są kompilowane w CI, a skrypt wydania sprawdza
zawartość pliku przed podpisaniem.
