package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var (
	// ErrAlreadyBootstrapped is returned by BootstrapAdmin when users exist.
	ErrAlreadyBootstrapped = errors.New("users already exist")
	// ErrLastAdmin is returned when a change would leave no enabled server
	// admin.
	ErrLastAdmin = errors.New("no enabled admin would be left")
)

// Key sources.
const (
	SourceManual = "manual"
	SourceGitHub = "github"
)

// User is an account. Keys belong to users.
type User struct {
	ID          int64
	Name        string
	GitHubLogin string // empty if the user was not added from GitHub
	IsAdmin     bool
	Disabled    bool
}

// Key is a registered public key.
type Key struct {
	ID          int64
	UserID      int64
	Fingerprint string // SHA256:...
	PublicKey   string // "<type> <base64>"
	KeyType     string
	Source      string
	LastUsedAt  string // UTC timestamp; empty if never used
}

// NewUser describes a user to create.
type NewUser struct {
	Name        string
	GitHubLogin string
	IsAdmin     bool
}

// NewKey describes a key to register. The caller is responsible for the key
// policy check; the store only records what it is given.
type NewKey struct {
	Fingerprint string
	PublicKey   string
	KeyType     string
	Source      string
}

// CountUsers returns the number of users, including disabled ones.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CreateUser creates a user with at least one key, atomically. It fails
// with ErrExists if the name is taken (names are case-insensitive) and with
// ErrKeyInUse if a key is registered already.
func (s *Store) CreateUser(ctx context.Context, u NewUser, keys []NewKey) (User, error) {
	return s.createUser(ctx, u, keys, false)
}

// BootstrapAdmin creates the first user as a server admin. It fails with
// ErrAlreadyBootstrapped if any user exists, so it cannot be used to add a
// second admin behind the first one's back.
func (s *Store) BootstrapAdmin(ctx context.Context, name, githubLogin string, keys []NewKey) (User, error) {
	return s.createUser(ctx, NewUser{Name: name, GitHubLogin: githubLogin, IsAdmin: true}, keys, true)
}

func (s *Store) createUser(ctx context.Context, u NewUser, keys []NewKey, onlyIfEmpty bool) (User, error) {
	if len(keys) == 0 {
		return User{}, errors.New("create user: at least one key is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if onlyIfEmpty {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
			return User{}, fmt.Errorf("create user: %w", err)
		}
		if n > 0 {
			return User{}, ErrAlreadyBootstrapped
		}
	}

	var taken bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE name = ?)`, u.Name).Scan(&taken); err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	if taken {
		return User{}, ErrExists
	}
	if err := keysFree(ctx, tx, keys); err != nil {
		return User{}, err
	}

	now := s.timestamp()
	res, err := tx.ExecContext(ctx,
		`INSERT INTO users (name, github_login, is_admin, created_at) VALUES (?, ?, ?, ?)`,
		u.Name, nullable(u.GitHubLogin), u.IsAdmin, now)
	if err != nil {
		return User{}, fmt.Errorf("create user %q: %w", u.Name, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	if err := insertKeys(ctx, tx, id, keys, now); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return User{ID: id, Name: u.Name, GitHubLogin: u.GitHubLogin, IsAdmin: u.IsAdmin}, nil
}

// DisableUser marks a user as disabled. Their keys stop authenticating
// immediately. It fails with ErrNotFound if there is no such enabled user,
// and with ErrLastAdmin if they are the only enabled server admin: with no
// admin left, nobody could manage accounts or create projects.
func (s *Store) DisableUser(ctx context.Context, userID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("disable user: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var isAdmin bool
	err = tx.QueryRowContext(ctx, `SELECT is_admin FROM users WHERE id = ? AND disabled_at IS NULL`, userID).Scan(&isAdmin)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("disable user: %w", err)
	}
	if isAdmin {
		var admins int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM users WHERE is_admin = 1 AND disabled_at IS NULL`).Scan(&admins); err != nil {
			return fmt.Errorf("disable user: %w", err)
		}
		if admins <= 1 {
			return ErrLastAdmin
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET disabled_at = ? WHERE id = ?`, s.timestamp(), userID); err != nil {
		return fmt.Errorf("disable user: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("disable user: %w", err)
	}
	return nil
}

// KeyByFingerprint returns the key with the given SHA256 fingerprint and
// its owner, or ErrNotFound. Disabled users are returned too: the caller
// decides what a disabled user may do.
func (s *Store) KeyByFingerprint(ctx context.Context, fingerprint string) (Key, User, error) {
	var (
		k        Key
		u        User
		login    sql.NullString
		disabled sql.NullString
		lastUsed sql.NullString
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT k.id, k.user_id, k.fingerprint_sha256, k.public_key, k.key_type, k.source, k.last_used_at,
		       u.name, u.github_login, u.is_admin, u.disabled_at
		FROM keys k JOIN users u ON u.id = k.user_id
		WHERE k.fingerprint_sha256 = ?`, fingerprint).Scan(
		&k.ID, &k.UserID, &k.Fingerprint, &k.PublicKey, &k.KeyType, &k.Source, &lastUsed,
		&u.Name, &login, &u.IsAdmin, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return Key{}, User{}, ErrNotFound
	}
	if err != nil {
		return Key{}, User{}, fmt.Errorf("look up key: %w", err)
	}
	u.ID = k.UserID
	u.GitHubLogin = login.String
	u.Disabled = disabled.Valid
	k.LastUsedAt = lastUsed.String
	return k, u, nil
}

// TouchKey records that a key was just used to authenticate.
func (s *Store) TouchKey(ctx context.Context, keyID int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE keys SET last_used_at = ? WHERE id = ?`, s.timestamp(), keyID)
	if err != nil {
		return fmt.Errorf("touch key: %w", err)
	}
	return nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
