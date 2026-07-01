# Contributing

Thanks for taking a look at gmacFTP. The project is intentionally small and native-first, so contributions should keep the app focused.

## Development Setup

```sh
cargo check
cargo test
cargo run
```

For the macOS app bundle:

```sh
bash scripts/build-app.sh
open target/release/gmacFTP.app
```

## Before Opening A Pull Request

- Run `cargo check`.
- Run relevant tests for the area you touched.
- Do not commit real server exports, passwords, personal paths, screenshots of private folders, or `.env` files.
- Keep UI changes consistent with the existing Slint token system.
- Keep the dual-pane model independent; the two panes must not be silently synchronized.

## Code Style

- Prefer small, focused patches.
- Keep protocol logic out of the Slint UI layer.
- Store passwords only through the credential store abstraction.
- Avoid new dependencies unless they remove meaningful complexity.

## Visual Changes

For UI work, include a short note describing what changed and which views were checked. Screenshots should use sample hosts and placeholder users only.
