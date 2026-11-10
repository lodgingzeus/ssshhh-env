package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func newKey(t *testing.T) *MasterKey {
	t.Helper()
	k, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newDEK(t *testing.T, k *MasterKey, projectID int64) (*DEK, Sealed) {
	t.Helper()
	dek, wrapped, err := k.NewDEK(projectID)
	if err != nil {
		t.Fatal(err)
	}
	return dek, wrapped
}

func TestVersionRoundTrip(t *testing.T) {
	dek, _ := newDEK(t, newKey(t), 1)
	ref := VersionRef{ProjectID: 1, EnvID: 2, Version: 3}
	for _, plaintext := range [][]byte{nil, []byte("A=1\n"), bytes.Repeat([]byte("x"), 256<<10)} {
		s, err := dek.SealVersion(ref, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if len(plaintext) > 0 && bytes.Contains(s.Ciphertext, plaintext) {
			t.Fatal("ciphertext contains the plaintext")
		}
		got, err := dek.OpenVersion(ref, s)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("round trip changed %d bytes of plaintext", len(plaintext))
		}
	}
}

func TestOpenVersionWrongKeyFails(t *testing.T) {
	k := newKey(t)
	dek, _ := newDEK(t, k, 1)
	other, _ := newDEK(t, k, 1)
	ref := VersionRef{ProjectID: 1, EnvID: 1, Version: 1}
	s, err := dek.SealVersion(ref, []byte("A=1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.OpenVersion(ref, s); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("err = %v, want ErrDecrypt", err)
	}
}

func TestOpenVersionTamperedFails(t *testing.T) {
	dek, _ := newDEK(t, newKey(t), 1)
	ref := VersionRef{ProjectID: 1, EnvID: 1, Version: 1}
	s, err := dek.SealVersion(ref, []byte("A=1\nB=2\n"))
	if err != nil {
		t.Fatal(err)
	}
	flip := func(b []byte, i int) []byte {
		out := bytes.Clone(b)
		out[i] ^= 0x01
		return out
	}
	tampered := map[string]Sealed{
		"first ciphertext byte": {Nonce: s.Nonce, Ciphertext: flip(s.Ciphertext, 0)},
		"last ciphertext byte":  {Nonce: s.Nonce, Ciphertext: flip(s.Ciphertext, len(s.Ciphertext)-1)},
		"truncated ciphertext":  {Nonce: s.Nonce, Ciphertext: s.Ciphertext[:len(s.Ciphertext)-1]},
		"empty ciphertext":      {Nonce: s.Nonce},
		"nonce":                 {Nonce: flip(s.Nonce, 0), Ciphertext: s.Ciphertext},
		"short nonce":           {Nonce: s.Nonce[:12], Ciphertext: s.Ciphertext},
		"no nonce":              {Ciphertext: s.Ciphertext},
	}
	for name, bad := range tampered {
		if _, err := dek.OpenVersion(ref, bad); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: err = %v, want ErrDecrypt", name, err)
		}
	}
}

// A ciphertext moved to another row must not decrypt, even under the right
// key (T11).
func TestOpenVersionWrongAADFails(t *testing.T) {
	dek, _ := newDEK(t, newKey(t), 1)
	ref := VersionRef{ProjectID: 1, EnvID: 2, Version: 3}
	s, err := dek.SealVersion(ref, []byte("A=1\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, other := range []VersionRef{
		{ProjectID: 9, EnvID: 2, Version: 3},
		{ProjectID: 1, EnvID: 9, Version: 3},
		{ProjectID: 1, EnvID: 2, Version: 9},
		{ProjectID: 2, EnvID: 1, Version: 3}, // same numbers, different fields
		{ProjectID: 3, EnvID: 2, Version: 1},
	} {
		if _, err := dek.OpenVersion(other, s); !errors.Is(err, ErrDecrypt) {
			t.Errorf("opened as %+v: err = %v, want ErrDecrypt", other, err)
		}
	}
}

func TestDEKWrapRoundTrip(t *testing.T) {
	k := newKey(t)
	dek, wrapped := newDEK(t, k, 7)
	if bytes.Contains(wrapped.Ciphertext, dek.key[:]) {
		t.Fatal("wrapped DEK contains the DEK")
	}
	got, err := k.UnwrapDEK(7, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if got.key != dek.key {
		t.Fatal("unwrapped DEK differs")
	}
}

func TestUnwrapDEKFails(t *testing.T) {
	k := newKey(t)
	_, wrapped := newDEK(t, k, 7)

	if _, err := newKey(t).UnwrapDEK(7, wrapped); !errors.Is(err, ErrDecrypt) {
		t.Errorf("wrong master key: err = %v, want ErrDecrypt", err)
	}
	if _, err := k.UnwrapDEK(8, wrapped); !errors.Is(err, ErrDecrypt) {
		t.Errorf("wrong project: err = %v, want ErrDecrypt", err)
	}
	bad := Sealed{Nonce: wrapped.Nonce, Ciphertext: bytes.Clone(wrapped.Ciphertext)}
	bad.Ciphertext[0] ^= 0x01
	if _, err := k.UnwrapDEK(7, bad); !errors.Is(err, ErrDecrypt) {
		t.Errorf("tampered: err = %v, want ErrDecrypt", err)
	}
}

// A wrapped DEK and a version are different kinds of ciphertext: neither
// may open as the other, even with matching ids and the same key bytes.
func TestDomainSeparation(t *testing.T) {
	k := newKey(t)
	asDEK := &DEK{key: k.key}
	_, wrapped := newDEK(t, k, 1)
	if _, err := asDEK.OpenVersion(VersionRef{ProjectID: 1, EnvID: 1, Version: 1}, wrapped); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrapped DEK opened as a version: err = %v", err)
	}
}

func TestNonPositiveIDsRefused(t *testing.T) {
	k := newKey(t)
	if _, _, err := k.NewDEK(0); err == nil {
		t.Error("NewDEK(0) succeeded")
	}
	if _, err := k.UnwrapDEK(-1, Sealed{}); err == nil {
		t.Error("UnwrapDEK(-1) succeeded")
	}
	dek, _ := newDEK(t, k, 1)
	for _, ref := range []VersionRef{{0, 1, 1}, {1, 0, 1}, {1, 1, 0}, {1, 1, -1}} {
		if _, err := dek.SealVersion(ref, []byte("x")); err == nil {
			t.Errorf("SealVersion(%+v) succeeded", ref)
		}
		if _, err := dek.OpenVersion(ref, Sealed{}); err == nil || errors.Is(err, ErrDecrypt) {
			t.Errorf("OpenVersion(%+v): err = %v, want a bad-id error", ref, err)
		}
	}
}

func TestNoncesAndKeysAreUnique(t *testing.T) {
	k := newKey(t)
	dek, _ := newDEK(t, k, 1)
	ref := VersionRef{ProjectID: 1, EnvID: 1, Version: 1}
	nonces := map[string]bool{}
	for range 10_000 {
		s, err := dek.SealVersion(ref, []byte("A=1\n"))
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Nonce) != 24 {
			t.Fatalf("nonce is %d bytes, want 24", len(s.Nonce))
		}
		if nonces[string(s.Nonce)] {
			t.Fatal("nonce repeated")
		}
		nonces[string(s.Nonce)] = true
	}
	deks := map[[KeySize]byte]bool{}
	for range 1000 {
		d, _ := newDEK(t, k, 1)
		if deks[d.key] {
			t.Fatal("DEK repeated")
		}
		deks[d.key] = true
	}
}

func TestKeysAreNotPrintable(t *testing.T) {
	k := newKey(t)
	dek, _ := newDEK(t, k, 1)
	secrets := []string{k.Encode(), string(k.key[:]), fmt.Sprint(k.key[:]), fmt.Sprint(dek.key[:])}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%x", "%q"} {
		out := fmt.Sprintf(format, k) + fmt.Sprintf(format, dek)
		for _, secret := range secrets {
			if bytes.Contains([]byte(out), []byte(secret)) {
				t.Errorf("format %s prints key material: %s", format, out)
			}
		}
	}
	// %x and %q go through String, so they print the redacted text.
	if got := fmt.Sprintf("%v", dek); got != "DEK(redacted)" {
		t.Errorf("DEK prints as %q", got)
	}
}
