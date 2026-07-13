# Migration fixtures

These password-free documents reproduce the public JSON shapes written by tagged gmacFTP
releases. They intentionally use only `example.com` endpoints, the `demo` account, and
`/Users/demo` paths.

- `v0.0.17`: minimal settings and connection metadata from the 0.0.x schema.
- `v0.1.1`: endpoint security/authentication fields introduced in the 0.1.x schema.
- `v0.2.0`: transfer, workspace, synchronization, and connection-management fields from 0.2.x.

Never replace these values with a real exported configuration. Secrets belong in the Keychain
vault and must not appear in migration fixtures.
