# passport-hash

Password hashing for [`passport`](https://github.com/shibisty/passport.go): **argon2id**
(the default, OWASP's first choice) and **bcrypt**, with one `Verify` for every format
the family writes, so stored hashes move to argon2id as users log in. Go package:
`passhash`. It is apart from the passport core because it needs `golang.org/x/crypto`;
the core's `passport/passwordhash` (PBKDF2) uses only the standard library.

## Installation

```bash
gtr add github:shibisty/passport.go github:shibisty/passport.go-hash
```

`passport` is a peer dependency (`^0.1`). Go 1.23+.

## Usage

```go
import passhash "passport-hash"

hash, err := passhash.Hash(password) // $argon2id$v=19$m=19456,t=2,p=1$<salt>$<key>

ok, err := passhash.Verify(password, stored) // argon2id, bcrypt or pbkdf2-sha256
if ok && passhash.NeedsRehash(stored) {      // another algorithm or weaker parameters
    stored, _ = passhash.Hash(password)       // save it with the user
}
```

With `passport-local`, check the password in the `VerifyFunc` and rehash there.

| Hasher | Format | Defaults |
|---|---|---|
| `passhash.Argon2id{}` | `$argon2id$v=19$m=…,t=…,p=…$salt$key` (PHC, as PHP and libsodium) | m = 19 MiB, t = 2, p = 1, 16-byte salt, 32-byte key |
| `passhash.Bcrypt{}` | `$2a$12$…` (verifies `$2b$`, `$2y$` too) | cost 12 |

- `passhash.Default` is the hasher of `Hash` and the policy of `NeedsRehash`; set it to
  `passhash.Argon2id{Memory: 65536, Time: 3}` for stronger parameters, and older hashes
  will be upgraded on login.
- bcrypt reads only 72 bytes of a password: longer ones are refused
  (`ErrPasswordTooLong`) instead of silently truncated.
- A corrupted or unknown hash is `ErrInvalidHash`; parameters from a hash are bounded
  (memory ≤ 4 GiB), so a planted hash cannot exhaust memory.
- Comparisons are in constant time.

## Tests

In a checkout, run `gtr install` once, then:

```bash
gtr run test -- -race -cover   # includes a reference argon2id vector
```

## License

MIT
