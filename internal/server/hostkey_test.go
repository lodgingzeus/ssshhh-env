package server

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateHostKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host_ed25519")

	s1, created, err := LoadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("first call: created = false")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %04o, want 0600", perm)
	}

	s2, created, err := LoadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("second call: created = true")
	}
	if !bytes.Equal(s1.PublicKey().Marshal(), s2.PublicKey().Marshal()) {
		t.Fatal("host key changed between loads")
	}
}

func TestLoadHostKeyRefusesLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host_ed25519")
	if _, _, err := LoadOrCreateHostKey(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateHostKey(path); err == nil {
		t.Fatal("0644 host key accepted")
	}
}
