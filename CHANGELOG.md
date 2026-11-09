# Changelog

## Unreleased

### Added
- `passhash.Argon2id` (PHC string format, OWASP defaults) and `passhash.Bcrypt` (cost 12,
  refuses passwords over 72 bytes); `Hash`, `Verify` (argon2id, bcrypt and passport's
  pbkdf2-sha256) and `NeedsRehash` with `Default` as the policy.
