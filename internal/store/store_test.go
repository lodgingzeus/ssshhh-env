package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func openTest(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func testKey(fp string) NewKey {
	return NewKey{Fingerprint: fp, PublicKey: "ssh-ed25519 AAAA" + fp, KeyType: "ssh-ed25519", Source: SourceManual}
}

func TestOpenCreatesPrivateFileInWALMode(t *testing.T) {
	s, path := openTest(t)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, NewUser{Name: "alice"}, []NewKey{testKey("SHA256:a")}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s: mode %04o, want 0600", filepath.Base(p), perm)
		}
	}
	for pragma, want := range map[string]string{"journal_mode": "wal", "foreign_keys": "1"} {
		var got string
		if err := s.db.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("PRAGMA %s = %q, want %q", pragma, got, want)
		}
	}
}

func TestOpenRefusesOpenPermissions(t *testing.T) {
	_, path := openTest(t)
	for _, mode := range []os.FileMode{0o640, 0o604, 0o660, 0o644} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if s, err := Open(context.Background(), path); err == nil {
			s.Close()
			t.Errorf("mode %04o accepted", mode)
		}
	}
}

func TestMigrationsAreIdempotentAndVersioned(t *testing.T) {
	s, path := openTest(t)
	ctx := context.Background()
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(ctx, path) // reopening must not re-apply anything
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != len(ms) {
		t.Fatalf("applied migrations = %d, want %d", n, len(ms))
	}

	// A database from a newer binary is refused, not silently used.
	if _, err := s.db.ExecContext(ctx, `INSERT INTO schema_migrations VALUES (?, 'future', 'x')`, len(ms)+1); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if s, err := Open(ctx, path); err == nil {
		s.Close()
		t.Fatal("opened a database with a newer schema version")
	}
}

func TestUsersAndKeys(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()

	alice, err := s.CreateUser(ctx, NewUser{Name: "alice", GitHubLogin: "alice-gh"}, []NewKey{testKey("SHA256:a1"), testKey("SHA256:a2")})
	if err != nil {
		t.Fatal(err)
	}
	k, u, err := s.KeyByFingerprint(ctx, "SHA256:a2")
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != alice.ID || u.Name != "alice" || u.GitHubLogin != "alice-gh" || u.IsAdmin || u.Disabled || k.UserID != alice.ID {
		t.Fatalf("got key %+v user %+v", k, u)
	}
	if _, _, err := s.KeyByFingerprint(ctx, "SHA256:nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown fingerprint: err = %v", err)
	}

	// Names are unique ignoring case; fingerprints are unique; a failed
	// create leaves nothing behind.
	if _, err := s.CreateUser(ctx, NewUser{Name: "ALICE"}, []NewKey{testKey("SHA256:b")}); err == nil {
		t.Error("duplicate name (different case) accepted")
	}
	if _, err := s.CreateUser(ctx, NewUser{Name: "bob"}, []NewKey{testKey("SHA256:b"), testKey("SHA256:a1")}); err == nil {
		t.Error("duplicate fingerprint accepted")
	}
	if _, err := s.CreateUser(ctx, NewUser{Name: "bob"}, nil); err == nil {
		t.Error("user without keys accepted")
	}
	if n, _ := s.CountUsers(ctx); n != 1 {
		t.Errorf("users = %d, want 1 (failed creates must roll back)", n)
	}
	if _, _, err := s.KeyByFingerprint(ctx, "SHA256:b"); !errors.Is(err, ErrNotFound) {
		t.Error("key from a rolled-back create exists")
	}

	if err := s.DisableUser(ctx, alice.ID); err != nil {
		t.Fatal(err)
	}
	if _, u, _ := s.KeyByFingerprint(ctx, "SHA256:a1"); !u.Disabled {
		t.Error("user not disabled")
	}
	if err := s.DisableUser(ctx, 999); !errors.Is(err, ErrNotFound) {
		t.Errorf("disable missing user: err = %v", err)
	}

	if err := s.TouchKey(ctx, k.ID); err != nil {
		t.Fatal(err)
	}
	var last string
	if err := s.db.QueryRowContext(ctx, `SELECT last_used_at FROM keys WHERE id = ?`, k.ID).Scan(&last); err != nil || last == "" {
		t.Errorf("last_used_at = %q, err = %v", last, err)
	}
}

func TestBootstrapAdminOnlyOnce(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()

	// Racing bootstraps: exactly one wins.
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := string(rune('a' + i))
			_, errs[i] = s.BootstrapAdmin(ctx, name, "", []NewKey{testKey("SHA256:" + name)})
		}()
	}
	wg.Wait()
	won := 0
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, ErrAlreadyBootstrapped):
			t.Errorf("unexpected error: %v", err)
		}
	}
	if won != 1 {
		t.Fatalf("%d bootstraps succeeded, want 1", won)
	}
	if n, _ := s.CountUsers(ctx); n != 1 {
		t.Fatalf("users = %d, want 1", n)
	}
	var admin bool
	if err := s.db.QueryRowContext(ctx, `SELECT is_admin FROM users`).Scan(&admin); err != nil || !admin {
		t.Fatalf("is_admin = %v, err = %v", admin, err)
	}
}

func TestAuditLogIsAppendOnly(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	u, err := s.CreateUser(ctx, NewUser{Name: "alice"}, []NewKey{testKey("SHA256:a")})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []AuditRow{
		{UserID: u.ID, KeyFingerprint: "SHA256:a", RemoteAddr: "127.0.0.1", Action: "whoami", Result: "ok"},
		{RemoteAddr: "10.0.0.1", Action: "auth", Result: "denied", Detail: "x"},
	} {
		if err := s.InsertAudit(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.ListAudit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Action != "auth" || rows[0].UserID != 0 || rows[1].UserID != u.ID || rows[1].Time == "" {
		t.Fatalf("rows = %+v", rows)
	}

	if err := s.InsertAudit(ctx, AuditRow{RemoteAddr: "x", Action: "x", Result: "maybe"}); err == nil {
		t.Error("invalid result accepted")
	}
	for _, q := range []string{`UPDATE audit_log SET result = 'ok'`, `DELETE FROM audit_log`} {
		if _, err := s.db.ExecContext(ctx, q); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s: err = %v, want append-only refusal", q, err)
		}
	}
	if rows, _ := s.ListAudit(ctx, 10); len(rows) != 2 || rows[0].Result != "denied" {
		t.Errorf("audit log changed: %+v", rows)
	}
}
