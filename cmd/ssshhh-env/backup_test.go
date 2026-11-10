package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lodgingzeus/ssshhh-env/internal/crypto"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// bootstrapped returns a data directory with one admin in it.
func bootstrapped(t *testing.T) string {
	t.Helper()
	dataDir := filepath.Join(t.TempDir(), "data")
	if code, _, stderr := cli("admin", "bootstrap", "--data-dir", dataDir, "--name", "alice", "--key", writeKeyFile(t, ed25519Key(t))); code != 0 {
		t.Fatalf("bootstrap: %s", stderr)
	}
	return dataDir
}

func loadKey(t *testing.T, path string) *crypto.MasterKey {
	t.Helper()
	k, err := crypto.LoadMasterKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestConfirmBackup(t *testing.T) {
	ctx := context.Background()
	os.Unsetenv(masterKeyEnv)
	dataDir := bootstrapped(t)
	keyFile := newMasterKeyFile(t)
	key := loadKey(t, keyFile)

	st := openDB(t, dataDir)
	if w, err := backupWarning(ctx, st, key, dataDir); err != nil || !strings.Contains(w, key.ID()) || !strings.Contains(w, "confirm-backup") {
		t.Fatalf("before confirming: warning %q, %v", w, err)
	}
	_ = st.Close()

	code, out, stderr := cli("admin", "confirm-backup", "--data-dir", dataDir, "--master-key-file", keyFile)
	if code != 0 || !strings.Contains(out, key.ID()) {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, stderr)
	}
	if strings.Contains(out+stderr, key.Encode()) {
		t.Fatal("key material printed")
	}

	st = openDB(t, dataDir)
	if w, err := backupWarning(ctx, st, key, dataDir); err != nil || w != "" {
		t.Errorf("after confirming: warning %q, %v", w, err)
	}
	// The confirmation names one key. Starting later with another key (the
	// database had no projects, so it is accepted) warns again.
	other := loadKey(t, newMasterKeyFile(t))
	if w, err := backupWarning(ctx, st, other, dataDir); err != nil || !strings.Contains(w, other.ID()) {
		t.Errorf("different key: warning %q, %v", w, err)
	}

	rows, err := st.ListAudit(ctx, 1)
	if err != nil || len(rows) != 1 {
		t.Fatalf("audit: %v, %d rows", err, len(rows))
	}
	if r := rows[0]; r.Action != "confirm-backup" || r.Target != key.ID() || r.Result != "ok" || r.RemoteAddr != "local" {
		t.Errorf("audit row = %+v", r)
	}
	if strings.Contains(rows[0].Detail+rows[0].Target, key.Encode()) {
		t.Error("key material in the audit log")
	}

	// Confirming twice is fine.
	if code, _, stderr := cli("admin", "confirm-backup", "--data-dir", dataDir, "--master-key-file", keyFile); code != 0 {
		t.Errorf("second confirm: %s", stderr)
	}
}

// A key the data isn't encrypted under can't be confirmed.
func TestConfirmBackupRefusesWrongKey(t *testing.T) {
	ctx := context.Background()
	os.Unsetenv(masterKeyEnv)
	dataDir := bootstrapped(t)
	original := loadKey(t, newMasterKeyFile(t))
	st := openDB(t, dataDir)
	if _, err := st.CreateProject(ctx, "app", 1, func(id int64) (store.WrappedDEK, error) {
		_, w, err := original.NewDEK(id)
		return store.WrappedDEK{Nonce: w.Nonce, Ciphertext: w.Ciphertext, MasterKeyID: original.ID()}, err
	}); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	wrongFile := newMasterKeyFile(t)
	code, _, stderr := cli("admin", "confirm-backup", "--data-dir", dataDir, "--master-key-file", wrongFile)
	if code == 0 || !strings.Contains(stderr, "wrong master key") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	st = openDB(t, dataDir)
	if ok, _ := st.MasterKeyBackupConfirmed(ctx, loadKey(t, wrongFile).ID()); ok {
		t.Error("wrong key recorded as backed up")
	}
}

func TestConfirmBackupRefusals(t *testing.T) {
	os.Unsetenv(masterKeyEnv)
	keyFile := newMasterKeyFile(t)

	// No server set up yet: refused, and nothing is created.
	missing := filepath.Join(t.TempDir(), "data")
	if code, _, stderr := cli("admin", "confirm-backup", "--data-dir", missing, "--master-key-file", keyFile); code == 0 || !strings.Contains(stderr, "bootstrap") {
		t.Errorf("no database: exit %d, %q", code, stderr)
	}
	if _, err := os.Stat(missing); err == nil {
		t.Error("data directory created")
	}

	dataDir := bootstrapped(t)
	if code, _, stderr := cli("admin", "confirm-backup", "--data-dir", dataDir); code == 0 || !strings.Contains(stderr, "no master key") {
		t.Errorf("no key: exit %d, %q", code, stderr)
	}
	if code, _, _ := cli("admin", "confirm-backup", "--data-dir", dataDir, "--master-key-file", keyFile, "extra"); code == 0 {
		t.Error("unexpected argument accepted")
	}
	if err := os.Chmod(keyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := cli("admin", "confirm-backup", "--data-dir", dataDir, "--master-key-file", keyFile); code == 0 || !strings.Contains(stderr, "too open") {
		t.Errorf("open key file: exit %d, %q", code, stderr)
	}
}

func TestVersion(t *testing.T) {
	for _, arg := range []string{"version", "--version"} {
		code, out, _ := cli(arg)
		if code != 0 || !strings.HasPrefix(out, "ssshhh-env ") {
			t.Errorf("%s: exit %d, %q", arg, code, out)
		}
	}
	old := version
	defer func() { version = old }()
	version = "v9.9.9"
	if _, out, _ := cli("version"); out != "ssshhh-env v9.9.9\n" {
		t.Errorf("release version: %q", out)
	}
}
