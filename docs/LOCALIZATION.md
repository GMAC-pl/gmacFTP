# Localization

gmacFTP ships English source text and a bundled Polish translation. The `System` preference uses
the first language reported by macOS; an explicit English or Polish selection overrides it. No
network service, telemetry, or online translation is involved.

## Static interface text

Wrap every new user-facing Slint string in `@tr(...)` and add its translation to
`translations/pl/LC_MESSAGES/gmacftp.po`. Use Slint placeholders and plural forms instead of
joining translated fragments when the whole sentence is known in the UI.

Protocol names, product names, keyboard glyphs, hashes, and literal example paths do not need
translation. The build embeds the catalog through `build.rs`; malformed or incompatible entries
make compilation fail.

## Operational messages

Messages containing paths, server replies, counts, or operating-system errors are assembled by
Rust. `src/i18n.rs` translates only known fixed text and fixed fragments, preserving all variable
details unchanged. Add a precise entry there when introducing a new message shown through a
runtime-localized status, summary, or error property. Never translate or redact a server detail by
guessing at its content.

## Checks

Run:

```sh
cargo test i18n::tests
cargo check --all-targets
```

The localization regression test verifies that every `@tr` source string has a Polish catalog
entry, that the old inline language conditionals do not return, and that the displayed app version
is not hard-coded.
