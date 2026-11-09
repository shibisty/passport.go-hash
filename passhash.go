// Package passhash hashes passwords with argon2id (the default, OWASP's
// first choice) or bcrypt, and verifies hashes of all three formats the
// passport family writes, so stored hashes can move to argon2id gradually:
//
//	hash, err := passhash.Hash(password)          // $argon2id$v=19$m=19456,t=2,p=1$...
//	ok, err := passhash.Verify(password, stored)  // argon2id, bcrypt ($2a$/$2b$/$2y$) or pbkdf2-sha256$
//	if ok && passhash.NeedsRehash(stored) {       // not argon2id, or weaker parameters
//	    stored, _ = passhash.Hash(password)        // save it
//	}
//
// gtr package: passport-hash. It is apart from the passport core because it
// needs golang.org/x/crypto, while the core uses only the standard library
// (passport/passwordhash: PBKDF2).
package passhash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"passport/passwordhash"
)

var (
	// ErrInvalidHash: the string is not a hash this package knows.
	ErrInvalidHash = errors.New("passhash: unknown or corrupted hash format")
	// ErrPasswordTooLong: bcrypt uses only the first 72 bytes; longer
	// passwords are refused instead of silently truncated (use argon2id).
	ErrPasswordTooLong = errors.New("passhash: bcrypt accepts at most 72 bytes of password")
)

// Hasher writes hashes of one algorithm with fixed parameters.
type Hasher interface {
	Hash(password string) (string, error)
	// Verify reports whether password matches a hash of this algorithm.
	Verify(password, hash string) (bool, error)
	// NeedsRehash reports whether hash was not written with this hasher's
	// algorithm and at least its parameters.
	NeedsRehash(hash string) bool
}

// Argon2id parameters; the zero value of a field takes the default.
type Argon2id struct {
	Memory  uint32 // KiB; default 19456 (19 MiB)
	Time    uint32 // passes; default 2
	Threads uint8  // default 1
	SaltLen int    // bytes; default 16
	KeyLen  uint32 // bytes; default 32
}

// Default is the hasher of Hash and the policy of NeedsRehash: argon2id with
// OWASP's parameters (m=19 MiB, t=2, p=1).
var Default Hasher = Argon2id{}

func (a Argon2id) params() Argon2id {
	if a.Memory == 0 {
		a.Memory = 19456
	}
	if a.Time == 0 {
		a.Time = 2
	}
	if a.Threads == 0 {
		a.Threads = 1
	}
	if a.SaltLen == 0 {
		a.SaltLen = 16
	}
	if a.KeyLen == 0 {
		a.KeyLen = 32
	}
	return a
}

var b64 = base64.RawStdEncoding

// Hash writes $argon2id$v=19$m=<memory>,t=<time>,p=<threads>$<salt>$<key>
// (the PHC string format, as libsodium and PHP write it).
func (a Argon2id) Hash(password string) (string, error) {
	p := a.params()
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.Memory, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

type argonHash struct {
	memory, time uint32
	threads      uint8
	salt, key    []byte
}

func parseArgon2id(hash string) (argonHash, error) {
	var h argonHash
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return h, ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return h, ErrInvalidHash
	}
	var threads uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &h.memory, &h.time, &threads); err != nil ||
		h.memory == 0 || h.time == 0 || threads == 0 || threads > 255 || h.memory > 4<<20 {
		return h, ErrInvalidHash
	}
	h.threads = uint8(threads)
	var err error
	if h.salt, err = b64.DecodeString(parts[4]); err != nil || len(h.salt) < 8 {
		return h, ErrInvalidHash
	}
	if h.key, err = b64.DecodeString(parts[5]); err != nil || len(h.key) < 16 {
		return h, ErrInvalidHash
	}
	return h, nil
}

func (a Argon2id) Verify(password, hash string) (bool, error) {
	h, err := parseArgon2id(hash)
	if err != nil {
		return false, err
	}
	key := argon2.IDKey([]byte(password), h.salt, h.time, h.memory, h.threads, uint32(len(h.key)))
	return subtle.ConstantTimeCompare(key, h.key) == 1, nil
}

func (a Argon2id) NeedsRehash(hash string) bool {
	h, err := parseArgon2id(hash)
	if err != nil {
		return true
	}
	p := a.params()
	return h.memory < p.Memory || h.time < p.Time || h.threads < p.Threads || uint32(len(h.key)) < p.KeyLen
}

// Bcrypt hashes with bcrypt; Cost 0 is 12.
type Bcrypt struct{ Cost int }

func (b Bcrypt) cost() int {
	if b.Cost == 0 {
		return 12
	}
	return b.Cost
}

func (b Bcrypt) Hash(password string) (string, error) {
	if len(password) > 72 {
		return "", ErrPasswordTooLong
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), b.cost())
	return string(h), err
}

func (b Bcrypt) Verify(password, hash string) (bool, error) {
	if !isBcrypt(hash) {
		return false, ErrInvalidHash
	}
	if len(password) > 72 {
		return false, nil
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
		return false, nil
	default:
		return false, ErrInvalidHash
	}
}

func (b Bcrypt) NeedsRehash(hash string) bool {
	c, err := bcrypt.Cost([]byte(hash))
	return err != nil || c < b.cost()
}

func isBcrypt(hash string) bool {
	return strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$")
}

// Hash hashes with Default (argon2id).
func Hash(password string) (string, error) { return Default.Hash(password) }

// Verify checks a password against a hash of any known format: argon2id,
// bcrypt or passport/passwordhash's pbkdf2-sha256.
func Verify(password, hash string) (bool, error) {
	switch {
	case strings.HasPrefix(hash, "$argon2id$"):
		return Argon2id{}.Verify(password, hash)
	case isBcrypt(hash):
		return Bcrypt{}.Verify(password, hash)
	case strings.HasPrefix(hash, "pbkdf2-sha256$"):
		ok, err := passwordhash.Verify(password, hash)
		if err != nil {
			return false, ErrInvalidHash
		}
		return ok, nil
	}
	return false, ErrInvalidHash
}

// NeedsRehash reports whether hash should be replaced by Hash after a
// successful login: another algorithm, or weaker parameters than Default.
func NeedsRehash(hash string) bool { return Default.NeedsRehash(hash) }

var (
	_ Hasher = Argon2id{}
	_ Hasher = Bcrypt{}
)
