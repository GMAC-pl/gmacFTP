# Privacy Checklist

This repository is intended to be public. Keep personal data and production credentials out of git.

## Never Commit

- `data/` exports from a third-party file manager, FileZilla, or any other FTP client
- Passwords, API tokens, SSH private keys, or `.env` files
- `.env.personal` or any other local private build identity file
- macOS Keychain exports
- App vault files from the user config directory
- Screenshots showing a real home directory, customer host, private domain, or private filename
- Local build products from `target/`
- Local tool state such as editor settings and `.DS_Store`

## Build Variants

`scripts/build-app.sh` can build both a personal bundle and a public bundle.

- The public bundle uses safe defaults from the tracked source tree.
- The personal bundle reads `.env.personal`, which is ignored by git and must stay local.
- Never copy values from `.env.personal` into tracked docs, scripts, screenshots, or CI.
- A selected SSH private-key **path** is local metadata only. The key is never copied, and the path
  is removed from cross-device synchronization metadata because it can reveal a macOS account name.

## Safe Demo Data

Use:

- `example.com` or localhost hosts
- `testuser` / `testpass` for local servers
- `/Users/demo/...` or `~/Downloads` for paths
- Small synthetic files in `/tmp`

## Update Checks

- The public app checks GitHub Releases only after a manual menu action or when the user explicitly
  enables one background check after launch. The background preference is off by default.
- Requests use fixed allow-listed HTTPS hosts and a generic `gmacFTP-updater` User-Agent. The app
  sends no account, saved-server data, file paths, stable device identifier, or analytics event.
  GitHub still receives ordinary connection metadata such as the source IP, as with any HTTPS
  request.
- A discovered release displays bounded release notes as plain text. It is never downloaded until
  the user confirms. The downloaded DMG is accepted only after size, SHA-256 digest, expected Apple
  Developer ID team, expected signing identifier, and stapled notarization checks pass.
- Personal/local bundles have a different bundle identity and do not run the public updater.

Po polsku: automatyczne sprawdzanie jest domyślnie wyłączone i wykonuje najwyżej jedno zapytanie po
uruchomieniu. Aplikacja nie wysyła telemetrii ani identyfikatora użytkownika; pobranie zawsze wymaga
osobnej zgody, a DMG jest otwierany dopiero po pełnej weryfikacji.

## Pre-Publish Scan

Run this before making the repository public:

```sh
git status --short
git ls-files
rg -n "password|secret|token|apikey|api_key|/Users/<local-user>|data/connections" . \
  --glob '!target/**' \
  --glob '!.git/**'
```

Review any matches manually. Some words may be legitimate documentation, but no real private value should remain.

## Screenshot Policy

Only screenshots under `docs/screenshots/` are intended for public documentation. They must use sample data and must not be taken from a real personal filesystem view.
