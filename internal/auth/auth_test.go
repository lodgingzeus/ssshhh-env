package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

func pubFrom(t *testing.T, key any) gossh.PublicKey {
	t.Helper()
	pub, err := gossh.NewPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func ed25519Pub(t *testing.T) gossh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pubFrom(t, pub)
}

func rsaPub(t *testing.T, bits int) gossh.PublicKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return pubFrom(t, &k.PublicKey)
}

func authorizedLine(pub gossh.PublicKey, name string) string {
	return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(pub))) + " " + name
}

func TestCheckKeyPolicy(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		pub  gossh.PublicKey
		ok   bool
	}{
		{"ed25519", ed25519Pub(t), true},
		{"ecdsa-p256", pubFrom(t, &ec.PublicKey), true},
		{"rsa-3072", rsaPub(t, 3072), true},
		{"rsa-2048", rsaPub(t, 2048), false},
		{"rsa-1024", rsaPub(t, 1024), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckKeyPolicy(tt.pub)
			if tt.ok && err != nil {
				t.Fatalf("want accepted, got %v", err)
			}
			if !tt.ok && !errors.Is(err, ErrWeakKey) {
				t.Fatalf("want ErrWeakKey, got %v", err)
			}
		})
	}
}

func TestCheckKeyPolicyRejectsCertificates(t *testing.T) {
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	ca, err := gossh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	cert := &gossh.Certificate{Key: ed25519Pub(t), CertType: gossh.UserCert, ValidBefore: gossh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	if err := CheckKeyPolicy(cert); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("want certificate refused, got %v", err)
	}
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func addUser(t *testing.T, st *store.Store, name string, admin bool, pubs ...gossh.PublicKey) store.User {
	t.Helper()
	var keys []store.NewKey
	for _, pub := range pubs {
		k, err := NewKey(pub, store.SourceManual)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
	}
	u, err := st.CreateUser(context.Background(), store.NewUser{Name: name, IsAdmin: admin}, keys)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestLookup(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	alice1, alice2, bob := ed25519Pub(t), ed25519Pub(t), ed25519Pub(t)
	alice := addUser(t, st, "alice", true, alice1, alice2)
	bobUser := addUser(t, st, "bob", false, bob)

	for _, pub := range []gossh.PublicKey{alice1, alice2} {
		id, err := Lookup(ctx, st, pub)
		if err != nil {
			t.Fatal(err)
		}
		if id.UserID != alice.ID || id.Name != "alice" || !id.IsAdmin || id.KeyID == 0 ||
			id.Fingerprint != Fingerprint(pub) || id.KeyType != gossh.KeyAlgoED25519 {
			t.Fatalf("Lookup = %+v", id)
		}
	}
	if id, err := Lookup(ctx, st, bob); err != nil || id.Name != "bob" || id.IsAdmin {
		t.Fatalf("Lookup(bob) = %+v, %v", id, err)
	}
	if _, err := Lookup(ctx, st, ed25519Pub(t)); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("stranger: err = %v", err)
	}
	if _, err := Lookup(ctx, st, nil); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("nil key: err = %v", err)
	}

	if err := st.DisableUser(ctx, bobUser.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := Lookup(ctx, st, bob); !errors.Is(err, ErrUserDisabled) {
		t.Fatalf("disabled user: err = %v", err)
	}
	if _, err := Lookup(ctx, st, alice1); err != nil {
		t.Fatalf("disabling bob affected alice: %v", err)
	}
}

// A weak key is refused even if it somehow got into the database.
func TestLookupAppliesPolicyToStoredKeys(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	weak := rsaPub(t, 2048)
	if _, err := NewKey(weak, store.SourceManual); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("NewKey(weak): err = %v", err)
	}
	if _, err := st.CreateUser(ctx, store.NewUser{Name: "old"}, []store.NewKey{{
		Fingerprint: Fingerprint(weak), PublicKey: MarshalKey(weak), KeyType: weak.Type(), Source: store.SourceManual,
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Lookup(ctx, st, weak); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("err = %v, want ErrWeakKey", err)
	}
}

// fakeKeys returns a fixed row whatever fingerprint is asked for.
type fakeKeys struct {
	key store.Key
	err error
}

func (f fakeKeys) KeyByFingerprint(context.Context, string) (store.Key, store.User, error) {
	return f.key, store.User{ID: 1, Name: "victim"}, f.err
}

func TestLookupFailsClosed(t *testing.T) {
	ctx := context.Background()
	pub, other := ed25519Pub(t), ed25519Pub(t)

	// The stored key differs from the presented one.
	mismatch := fakeKeys{key: store.Key{ID: 1, UserID: 1, Fingerprint: Fingerprint(pub), PublicKey: MarshalKey(other)}}
	if _, err := Lookup(ctx, mismatch, pub); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("mismatched key: err = %v", err)
	}
	// A storage failure is an error, never an identity.
	broken := fakeKeys{err: errors.New("disk on fire")}
	if id, err := Lookup(ctx, broken, pub); err == nil || id != (Identity{}) {
		t.Fatalf("storage failure: id = %+v, err = %v", id, err)
	}
}

func TestParsePublicKeys(t *testing.T) {
	a, b := ed25519Pub(t), ed25519Pub(t)
	data := "# comment\n\n" + authorizedLine(a, "alice@laptop") + "\n" + MarshalKey(b) + "\n" + MarshalKey(a) + "\n"
	keys, err := ParsePublicKeys([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || Fingerprint(keys[0]) != Fingerprint(a) || Fingerprint(keys[1]) != Fingerprint(b) {
		t.Fatalf("got %d keys", len(keys))
	}
	if keys, err := ParsePublicKeys([]byte("\n# nothing\n")); err != nil || len(keys) != 0 {
		t.Fatalf("empty input: %d keys, err = %v", len(keys), err)
	}
	for name, bad := range map[string]string{
		"garbage":     "not a key",
		"options":     `command="/bin/sh" ` + MarshalKey(a),
		"private key": "-----BEGIN OPENSSH PRIVATE KEY-----",
	} {
		_, err := ParsePublicKeys([]byte(bad))
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "BEGIN") {
			t.Errorf("%s: error echoes the input: %v", name, err)
		}
	}
}

func TestValidName(t *testing.T) {
	for _, ok := range []string{"alice", "Alice-2", "a", "bob.smith_x", strings.Repeat("a", 64)} {
		if !ValidName(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "-rf", ".hidden", "evil\x1b[31m", "two words", "a/b", "a@b", strings.Repeat("a", 65), "alice\n"} {
		if ValidName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
