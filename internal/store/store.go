// Package store is the SQLite persistence layer.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, registered as "sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// timeFormat is how every timestamp is stored: UTC, fixed width, sortable.
const timeFormat = "2006-01-02T15:04:05Z"

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// Store is a handle to the database. It is safe for concurrent use.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Open opens the database at path, creating it with mode 0600 if needed, and
// applies any pending migrations. An existing file that is readable or
// writable by group or others is refused.
func Open(ctx context.Context, path string) (*Store, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- operator-supplied path from a CLI flag
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	fi, err := f.Stat()
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("database %s is not a regular file", path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("database %s: mode %04o is too open, want 0600", path, perm)
	}

	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "synchronous(FULL)")
	// Take the write lock at BEGIN, so concurrent writers wait on
	// busy_timeout instead of failing halfway through a transaction.
	q.Set("_txlock", "immediate")
	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: q.Encode()}).String()

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	s := &Store{db: db, now: time.Now}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) timestamp() string { return s.now().UTC().Format(timeFormat) }

type migration struct {
	version int
	name    string
	sql     string
}

// loadMigrations reads the embedded files, named "<version>_<name>.sql".
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	var ms []migration
	for _, e := range entries {
		prefix, _, ok := strings.Cut(e.Name(), "_")
		v, err := strconv.Atoi(prefix)
		if !ok || err != nil || v <= 0 {
			return nil, fmt.Errorf("migration %q: name must start with a version number", e.Name())
		}
		data, err := fs.ReadFile(migrationFS, "migrations/"+e.Name())
		if err != nil {
			return nil, err
		}
		ms = append(ms, migration{version: v, name: e.Name(), sql: string(data)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	for i, m := range ms {
		if m.version != i+1 {
			return nil, fmt.Errorf("migration %q: versions must be 1..n without gaps", m.name)
		}
	}
	return ms, nil
}

// migrate applies pending migrations, each in its own transaction. A
// database written by a newer binary is refused.
func (s *Store) migrate(ctx context.Context) error {
	ms, err := loadMigrations()
	if err != nil {
		return fmt.Errorf("migrations: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL) STRICT`); err != nil {
		return fmt.Errorf("migrations: %w", err)
	}
	for {
		done, err := s.migrateOne(ctx, ms)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
}

// migrateOne applies the next pending migration. It re-reads the current
// version inside the transaction, so two processes starting together don't
// both apply the same one.
func (s *Store) migrateOne(ctx context.Context, ms []migration) (done bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("migrations: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var current int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return false, fmt.Errorf("migrations: %w", err)
	}
	if current > len(ms) {
		return false, fmt.Errorf("database schema version %d is newer than this binary supports (%d)", current, len(ms))
	}
	if current == len(ms) {
		return true, nil
	}
	m := ms[current]
	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return false, fmt.Errorf("migration %s: %w", m.name, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
		m.version, m.name, s.timestamp()); err != nil {
		return false, fmt.Errorf("migration %s: %w", m.name, err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("migration %s: %w", m.name, err)
	}
	return false, nil
}
