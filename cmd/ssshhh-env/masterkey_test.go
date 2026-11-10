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

// newMasterKeyFile writes a fresh master key with keygen-master --out.
func newMasterKeyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "master.key")
	if code, _, stderr := cli("keygen-master", "--out", path); code != 0 {
		t.Fatalf("keygen-master: exit %d, %s", code, stderr)
	}
	return path
}

func TestKeygenMasterToStdout(t *testing.T) {
	code, out, stderr := cli("keygen-master")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	// stdout is the key and nothing else, so it can be redirected to a file.
	key, err := crypto.ParseMasterKey(out)
	if err != nil || len(strings.TrimSpace(out)) != 44 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("stdout %q is not just a key: %v", out, err)
	}
	if strings.Contains(stderr, strings.TrimSpace(out)) {
		t.Error("key repeated on stderr")
	}
	if !strings.Contains(stderr, key.ID()) || !strings.Contains(stderr, "Back it up") || !strings.Contains(stderr, "chmod 600") {
		t.Errorf("stderr lacks the key id or the handling advice: %q", stderr)
	}

	_, again, _ := cli("keygen-master")
	if again == out {
		t.Fatal("two runs produced the same key")
	}
	if code, _, _ := cli("keygen-master", "extra"); code == 0 {
		t.Error("unexpected argument accepted")
	}
}

func TestKeygenMasterToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	code, out, stderr := cli("keygen-master", "--out", path)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %04o, want 0600", fi.Mode().Perm())
	}
	key, err := crypto.LoadMasterKeyFile(path)
	if err != nil {
		t.Fatalf("written file does not load: %v", err)
	}
	if out != "" || strings.Contains(stderr, key.Encode()) {
		t.Errorf("key printed as well as written: stdout %q, stderr %q", out, stderr)
	}

	// Never overwrite: the existing file may be the only copy of a key.
	before, _ := os.ReadFile(path)
	code, _, stderr = cli("keygen-master", "--out", path)
	if code == 0 || !strings.Contains(stderr, "already exists") {
		t.Fatalf("overwrite: exit %d, stderr %q", code, stderr)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("existing key file was changed")
	}
}

func TestLoadMasterKey(t *testing.T) {
	file := newMasterKeyFile(t)
	fromFile, err := crypto.LoadMasterKeyFile(file)
	if err != nil {
		t.Fatal(err)
	}
	other, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}

	unset := func(t *testing.T) {
		t.Setenv(masterKeyEnv, "") // registers the restore
		os.Unsetenv(masterKeyEnv)
	}

	t.Run("file", func(t *testing.T) {
		unset(t)
		if key, err := loadMasterKey(file); err != nil || key.ID() != fromFile.ID() {
			t.Fatalf("key %v, err %v", key, err)
		}
	})
	t.Run("env", func(t *testing.T) {
		t.Setenv(masterKeyEnv, other.Encode())
		key, err := loadMasterKey("")
		if err != nil || key.ID() != other.ID() {
			t.Fatalf("key %v, err %v", key, err)
		}
		if _, still := os.LookupEnv(masterKeyEnv); still {
			t.Error("the key was left in the environment")
		}
	})
	t.Run("neither", func(t *testing.T) {
		unset(t)
		if _, err := loadMasterKey(""); err == nil || !strings.Contains(err.Error(), "keygen-master") {
			t.Fatalf("err = %v, want a hint to generate a key", err)
		}
	})
	t.Run("both", func(t *testing.T) {
		t.Setenv(masterKeyEnv, other.Encode())
		if _, err := loadMasterKey(file); err == nil || !strings.Contains(err.Error(), "only one") {
			t.Fatalf("err = %v, want a refusal to choose", err)
		}
	})
	t.Run("empty env counts as set", func(t *testing.T) {
		t.Setenv(masterKeyEnv, "")
		if _, err := loadMasterKey(""); err == nil || !strings.Contains(err.Error(), masterKeyEnv) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("bad env value is not echoed", func(t *testing.T) {
		t.Setenv(masterKeyEnv, "CANARY-not-a-key")
		_, err := loadMasterKey("")
		if err == nil || strings.Contains(err.Error(), "CANARY") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("file too open", func(t *testing.T) {
		unset(t)
		if err := os.Chmod(file, 0o644); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(file, 0o600)
		if _, err := loadMasterKey(file); err == nil || !strings.Contains(err.Error(), "too open") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestServeRefusesWithoutMasterKey(t *testing.T) {
	t.Setenv(masterKeyEnv, "")
	os.Unsetenv(masterKeyEnv)
	dataDir := filepath.Join(t.TempDir(), "data")
	code, _, stderr := cli("serve", "--data-dir", dataDir, "--addr", "127.0.0.1:0")
	if code == 0 || !strings.Contains(stderr, "no master key") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if _, err := os.Stat(dataDir); err == nil {
		t.Error("data directory created by a refused start")
	}
}

// A master key that can't decrypt the existing projects is caught at
// startup, before the host key is created or a port is opened.
func TestServeRefusesWrongMasterKey(t *testing.T) {
	ctx := context.Background()
	dataDir := filepath.Join(t.TempDir(), "data")
	if code, _, stderr := cli("admin", "bootstrap", "--data-dir", dataDir, "--name", "alice", "--key", writeKeyFile(t, ed25519Key(t))); code != 0 {
		t.Fatalf("bootstrap: %s", stderr)
	}
	original, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	st := openDB(t, dataDir)
	_, err = st.CreateProject(ctx, "app", 1, func(id int64) (store.WrappedDEK, error) {
		_, w, err := original.NewDEK(id)
		return store.WrappedDEK{Nonce: w.Nonce, Ciphertext: w.Ciphertext, MasterKeyID: original.ID()}, err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := cli("serve", "--data-dir", dataDir, "--addr", "127.0.0.1:0", "--master-key-file", newMasterKeyFile(t))
	if code == 0 || !strings.Contains(stderr, "wrong master key") || !strings.Contains(stderr, original.ID()) {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "host_ed25519")); err == nil {
		t.Error("host key created by a refused start")
	}

	// checkMasterKey accepts the right key and an empty database.
	st = openDB(t, dataDir)
	if err := checkMasterKey(ctx, st, original); err != nil {
		t.Errorf("right key refused: %v", err)
	}
}
