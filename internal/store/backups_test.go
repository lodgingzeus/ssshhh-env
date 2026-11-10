package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMasterKeyBackupConfirmation(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()

	ok, err := s.MasterKeyBackupConfirmed(ctx, "mk-a")
	if err != nil || ok {
		t.Fatalf("fresh database: confirmed = %v, %v", ok, err)
	}
	if err := s.ConfirmMasterKeyBackup(ctx, ""); err == nil {
		t.Error("empty key id accepted")
	}

	first := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	s.now = func() time.Time { return first }
	if err := s.ConfirmMasterKeyBackup(ctx, "mk-a"); err != nil {
		t.Fatal(err)
	}
	// Confirming again is not an error and keeps the first time.
	s.now = func() time.Time { return first.Add(time.Hour) }
	if err := s.ConfirmMasterKeyBackup(ctx, "mk-a"); err != nil {
		t.Fatal(err)
	}
	var at string
	if err := s.db.QueryRowContext(ctx, `SELECT confirmed_at FROM master_key_backups WHERE key_id = 'mk-a'`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	if at != first.Format(timeFormat) {
		t.Errorf("confirmed_at = %s, want the first confirmation %s", at, first.Format(timeFormat))
	}

	if ok, err := s.MasterKeyBackupConfirmed(ctx, "mk-a"); err != nil || !ok {
		t.Errorf("mk-a: confirmed = %v, %v", ok, err)
	}
	// A confirmation is per key: a different key is not covered.
	if ok, err := s.MasterKeyBackupConfirmed(ctx, "mk-b"); err != nil || ok {
		t.Errorf("mk-b: confirmed = %v, %v", ok, err)
	}
}

// A database written by an earlier release (schema 0001-0002) is upgraded
// in place and keeps its data.
func TestUpgradeFromEarlierSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) < 3 {
		t.Fatalf("expected at least 3 migrations, have %d", len(ms))
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	old := &Store{db: db, now: time.Now}
	if _, err := db.ExecContext(ctx, `CREATE TABLE schema_migrations (
		version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	for {
		done, err := old.migrateOne(ctx, ms[:2])
		if err != nil {
			t.Fatal(err)
		}
		if done {
			break
		}
	}
	if _, err := old.BootstrapAdmin(ctx, "alice", "", []NewKey{testKey("fp1")}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer s.Close()
	var version int
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != len(ms) {
		t.Errorf("schema version = %d, want %d", version, len(ms))
	}
	if n, err := s.CountUsers(ctx); err != nil || n != 1 {
		t.Errorf("users after upgrade = %d, %v", n, err)
	}
	if ok, err := s.MasterKeyBackupConfirmed(ctx, "any"); err != nil || ok {
		t.Errorf("new table: confirmed = %v, %v", ok, err)
	}
}
