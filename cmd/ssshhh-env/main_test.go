package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/lodgingzeus/ssshhh-env/internal/auth"
	"github.com/lodgingzeus/ssshhh-env/internal/github"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

func ed25519Key(t *testing.T) gossh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func weakRSAKey(t *testing.T) gossh.PublicKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	k, err := gossh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func writeKeyFile(t *testing.T, keys ...gossh.PublicKey) string {
	t.Helper()
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(auth.MarshalKey(k) + " someone@laptop\n")
	}
	path := filepath.Join(t.TempDir(), "id.pub")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// cli runs the command line and returns the exit code, stdout and stderr.
func cli(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func openDB(t *testing.T, dataDir string) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(dataDir, dbName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestBootstrapWithKeyFile(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	key := ed25519Key(t)
	code, out, stderr := cli("admin", "bootstrap", "--data-dir", dataDir, "--name", "alice", "--key", writeKeyFile(t, key))
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(out, auth.Fingerprint(key)) || !strings.Contains(out, `"alice"`) {
		t.Errorf("output = %q", out)
	}

	if fi, err := os.Stat(dataDir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("data dir: %v, %v", fi.Mode().Perm(), err)
	}
	if fi, err := os.Stat(filepath.Join(dataDir, dbName)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("database: %v, %v", fi.Mode().Perm(), err)
	}

	st := openDB(t, dataDir)
	id, err := auth.Lookup(context.Background(), st, key)
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "alice" || !id.IsAdmin {
		t.Fatalf("identity = %+v", id)
	}
	k, u, _ := st.KeyByFingerprint(context.Background(), auth.Fingerprint(key))
	if k.Source != store.SourceManual || u.GitHubLogin != "" {
		t.Errorf("key source %q, github login %q", k.Source, u.GitHubLogin)
	}
	rows, err := st.ListAudit(context.Background(), 10)
	if err != nil || len(rows) != 1 || rows[0].Action != "bootstrap" || rows[0].Result != "ok" || rows[0].UserID != id.UserID {
		t.Errorf("audit rows = %+v, err = %v", rows, err)
	}

	// A second bootstrap must not create another admin.
	other := ed25519Key(t)
	code, _, stderr = cli("admin", "bootstrap", "--data-dir", dataDir, "--name", "mallory", "--key", writeKeyFile(t, other))
	if code == 0 || !strings.Contains(stderr, "already has users") {
		t.Fatalf("second bootstrap: exit %d, stderr %q", code, stderr)
	}
	if _, err := auth.Lookup(context.Background(), st, other); err == nil {
		t.Fatal("second bootstrap registered a key")
	}
	if n, _ := st.CountUsers(context.Background()); n != 1 {
		t.Fatalf("users = %d, want 1", n)
	}
}

func TestBootstrapWithGitHub(t *testing.T) {
	good, weak := ed25519Key(t), weakRSAKey(t)
	var requested string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = r.URL.Path
		_, _ = w.Write([]byte(auth.MarshalKey(weak) + "\n" + auth.MarshalKey(good) + "\n"))
	}))
	defer srv.Close()
	old := githubClient
	githubClient = github.Client{BaseURL: srv.URL}
	defer func() { githubClient = old }()

	dataDir := filepath.Join(t.TempDir(), "data")
	code, out, stderr := cli("admin", "bootstrap", "--data-dir", dataDir, "--github", "Octo-Cat")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if requested != "/Octo-Cat.keys" {
		t.Errorf("requested %q", requested)
	}
	if !strings.Contains(out, auth.Fingerprint(good)) || !strings.Contains(out, "pinned") {
		t.Errorf("output = %q", out)
	}
	// The weak key is reported and left out.
	if !strings.Contains(stderr, auth.Fingerprint(weak)) || strings.Contains(out, auth.Fingerprint(weak)) {
		t.Errorf("weak key handling: stdout %q, stderr %q", out, stderr)
	}

	st := openDB(t, dataDir)
	k, u, err := st.KeyByFingerprint(context.Background(), auth.Fingerprint(good))
	if err != nil {
		t.Fatal(err)
	}
	if u.Name != "Octo-Cat" || u.GitHubLogin != "Octo-Cat" || !u.IsAdmin || k.Source != store.SourceGitHub {
		t.Errorf("user %+v, key source %q", u, k.Source)
	}
	if _, _, err := st.KeyByFingerprint(context.Background(), auth.Fingerprint(weak)); err == nil {
		t.Error("weak key was registered")
	}
}

func TestBootstrapRefusals(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	old := githubClient
	githubClient = github.Client{BaseURL: srv.URL}
	defer func() { githubClient = old }()

	good := writeKeyFile(t, ed25519Key(t))
	private := filepath.Join(t.TempDir(), "id")
	if err := os.WriteFile(private, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nc2VjcmV0\n-----END OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := map[string][]string{
		"no source":        {"--name", "alice"},
		"both sources":     {"--name", "alice", "--key", good, "--github", "octocat"},
		"key without name": {"--key", good},
		"bad name":         {"--name", "-rf", "--key", good},
		"name with escape": {"--name", "a\x1b[31m", "--key", good},
		"bad github login": {"--github", "../etc/passwd"},
		"unknown github":   {"--github", "nobody"},
		"missing key file": {"--name", "alice", "--key", filepath.Join(t.TempDir(), "nope.pub")},
		"private key file": {"--name", "alice", "--key", private},
		"only weak keys":   {"--name", "alice", "--key", writeKeyFile(t, weakRSAKey(t))},
		"empty key file":   {"--name", "alice", "--key", writeKeyFile(t)},
		"stray argument":   {"--name", "alice", "--key", good, "extra"},
		"unknown flag":     {"--admin"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			dataDir := filepath.Join(t.TempDir(), "data")
			code, _, stderr := cli(append([]string{"admin", "bootstrap", "--data-dir", dataDir}, args...)...)
			if code == 0 {
				t.Fatal("succeeded")
			}
			if strings.Contains(stderr, "c2VjcmV0") {
				t.Errorf("stderr echoes key file contents: %q", stderr)
			}
			if _, err := os.Stat(filepath.Join(dataDir, dbName)); err == nil {
				if n, _ := openDB(t, dataDir).CountUsers(context.Background()); n != 0 {
					t.Errorf("a refused bootstrap created %d user(s)", n)
				}
			}
		})
	}
}

func TestBootstrapRefusesOpenDataDir(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := cli("admin", "bootstrap", "--data-dir", dataDir, "--name", "alice", "--key", writeKeyFile(t, ed25519Key(t)))
	if code == 0 || !strings.Contains(stderr, "too open") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

// Starting with no users fails with a hint, before the host key is created.
func TestServeRefusesWithoutUsers(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	code, _, stderr := cli("serve", "--data-dir", dataDir, "--addr", "127.0.0.1:0")
	if code == 0 || !strings.Contains(stderr, "admin bootstrap") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stderr, dataDir) {
		t.Errorf("hint does not name the absolute data dir: %q", stderr)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "host_ed25519")); err == nil {
		t.Error("host key created by a refused start")
	}
}

func TestAdminUsage(t *testing.T) {
	if code, _, stderr := cli("admin"); code == 0 || !strings.Contains(stderr, "bootstrap") {
		t.Errorf("admin: exit %d, stderr %q", code, stderr)
	}
	if code, _, _ := cli("admin", "nope"); code == 0 {
		t.Error("admin nope succeeded")
	}
	if code, out, _ := cli("admin", "help"); code != 0 || !strings.Contains(out, "bootstrap") {
		t.Errorf("admin help: exit %d, out %q", code, out)
	}
}
