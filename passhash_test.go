package passhash

import (
	"errors"
	"strings"
	"testing"

	"passport/passwordhash"
)

func TestArgon2id(t *testing.T) {
	h, err := Hash("correct horse")
	if err != nil || !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("Hash = %q, %v", h, err)
	}
	if h2, _ := Hash("correct horse"); h2 == h {
		t.Fatal("no salt")
	}
	if ok, err := Verify("correct horse", h); !ok || err != nil {
		t.Fatalf("Verify: %v %v", ok, err)
	}
	if ok, _ := Verify("wrong", h); ok {
		t.Fatal("wrong password accepted")
	}
	if NeedsRehash(h) {
		t.Fatal("fresh hash needs rehash")
	}
	weak, _ := Argon2id{Memory: 8192, Time: 1}.Hash("x")
	if !NeedsRehash(weak) {
		t.Fatal("weak parameters do not need rehash")
	}
	if ok, _ := Verify("x", weak); !ok {
		t.Fatal("weak hash does not verify")
	}
	// A hash from another implementation (PHP password_hash, libsodium):
	// argon2id of "password" with salt "somesalt" (m=65536,t=2,p=1).
	php := "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"
	if ok, err := Verify("password", php); !ok || err != nil {
		t.Fatalf("reference vector: %v %v", ok, err)
	}
	for _, bad := range []string{
		"$argon2id$v=18$m=1,t=1,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
		"$argon2id$v=19$m=0,t=1,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
		"$argon2id$v=19$m=99999999,t=1,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
		"$argon2id$v=19$m=65536,t=2,p=1$!!$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
		"$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$!!",
		"$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ",
		"$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFh",
		"plain",
	} {
		if _, err := Verify("password", bad); !errors.Is(err, ErrInvalidHash) {
			t.Errorf("Verify(%q) = %v", bad, err)
		}
		if !NeedsRehash(bad) {
			t.Errorf("NeedsRehash(%q) = false", bad)
		}
	}
}

func TestBcrypt(t *testing.T) {
	b := Bcrypt{Cost: 4}
	h, err := b.Hash("pw")
	if err != nil || !strings.HasPrefix(h, "$2a$04$") {
		t.Fatalf("Hash = %q, %v", h, err)
	}
	if ok, err := Verify("pw", h); !ok || err != nil {
		t.Fatalf("Verify: %v %v", ok, err)
	}
	if ok, _ := Verify("nope", h); ok {
		t.Fatal("wrong password accepted")
	}
	if !NeedsRehash(h) || !(Bcrypt{}).NeedsRehash(h) || b.NeedsRehash(h) {
		t.Fatal("NeedsRehash")
	}
	long := strings.Repeat("a", 73)
	if _, err := b.Hash(long); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("long password: %v", err)
	}
	if ok, err := b.Verify(long, h); ok || err != nil {
		t.Fatalf("long password verify: %v %v", ok, err)
	}
	if _, err := b.Verify("pw", "$2a$04$short"); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("corrupted bcrypt: %v", err)
	}
	if _, err := b.Verify("pw", "$argon2id$x"); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("not bcrypt: %v", err)
	}
	if (Bcrypt{}).cost() != 12 {
		t.Fatal("default cost")
	}
}

func TestPBKDF2Migration(t *testing.T) {
	old, err := passwordhash.Hash("legacy")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := Verify("legacy", old); !ok || err != nil {
		t.Fatalf("pbkdf2 hash: %v %v", ok, err)
	}
	if !NeedsRehash(old) {
		t.Fatal("pbkdf2 hash should move to argon2id")
	}
	if _, err := Verify("legacy", "pbkdf2-sha256$x"); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("corrupted pbkdf2: %v", err)
	}
}
