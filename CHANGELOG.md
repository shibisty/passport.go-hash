# Changelog

## Unreleased

## 0.1.1 — 2026-11-09

### Changed
- Requires `passport ^0.2` (the first published release of the core; `^0.1` matched no tag).

### Added
- `passhash.Argon2id` (PHC string format, OWASP defaults) and `passhash.Bcrypt` (cost 12,
  refuses passwords over 72 bytes); `Hash`, `Verify` (argon2id, bcrypt and passport's
  pbkdf2-sha256) and `NeedsRehash` with `Default` as the policy.
