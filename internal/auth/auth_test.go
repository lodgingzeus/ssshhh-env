package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
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

func TestParseAllowlist(t *testing.T) {
	alice := ed25519Pub(t)
	bob := ed25519Pub(t)
	stranger := ed25519Pub(t)

	data := "# comment\n\n" + authorizedLine(alice, "alice") + "\n" + authorizedLine(bob, "bob@laptop") + "\n"
	a, err := parseAllowlist([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if a.Len() != 2 {
		t.Fatalf("Len = %d, want 2", a.Len())
	}
	id, ok := a.Lookup(alice)
	if !ok || id.Name != "alice" || id.Fingerprint != Fingerprint(alice) || id.KeyType != gossh.KeyAlgoED25519 {
		t.Fatalf("Lookup(alice) = %+v, %v", id, ok)
	}
	if id, ok := a.Lookup(bob); !ok || id.Name != "bob@laptop" {
		t.Fatalf("Lookup(bob) = %+v, %v", id, ok)
	}
	if _, ok := a.Lookup(stranger); ok {
		t.Fatal("stranger allowed")
	}
	if _, ok := a.Lookup(nil); ok {
		t.Fatal("nil key allowed")
	}
}

func TestParseAllowlistRejects(t *testing.T) {
	k := ed25519Pub(t)
	tests := map[string]string{
		"weak rsa":       authorizedLine(rsaPub(t, 2048), "weak"),
		"options":        `command="/bin/sh" ` + authorizedLine(k, "opt"),
		"no name":        strings.TrimSpace(string(gossh.MarshalAuthorizedKey(k))),
		"control chars":  authorizedLine(k, "evil\x1b[31m"),
		"duplicate":      authorizedLine(k, "a") + "\n" + authorizedLine(k, "b"),
		"garbage":        "not a key",
		"name too long":  authorizedLine(k, strings.Repeat("a", 65)),
		"leading symbol": authorizedLine(k, "-rf"),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseAllowlist([]byte(data)); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestLoadAllowlistPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(path, []byte(authorizedLine(ed25519Pub(t), "alice")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAllowlist(path); err != nil {
		t.Fatalf("0600: %v", err)
	}
	if err := os.Chmod(path, 0o620); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAllowlist(path); err == nil {
		t.Fatal("group-writable file accepted")
	}
	if _, err := LoadAllowlist(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: got %v", err)
	}
}
