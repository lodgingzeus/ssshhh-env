package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
)

var (
	// ErrKeyInUse is returned when a key is already registered to a user.
	// A key identifies exactly one user.
	ErrKeyInUse = errors.New("key already registered")
	// ErrLastKey is returned when removing a key would leave its user with
	// none. Disabling the user is the way to lock them out.
	ErrLastKey = errors.New("user would have no keys")
)

// UserSummary is a user with the number of keys they have.
type UserSummary struct {
	User
	Keys int
}

// KeyChanges lists the fingerprints a key replacement added and removed.
type KeyChanges struct {
	Added   []string
	Removed []string
}

// UserByName returns the user called name (case-insensitive), or
// ErrNotFound. Disabled users are returned too.
func (s *Store) UserByName(ctx context.Context, name string) (User, error) {
	return s.user(ctx, `u.name = ?`, name)
}

// UserByGitHubLogin returns the user added from that GitHub account
// (case-insensitive), or ErrNotFound. Disabled users are returned too.
func (s *Store) UserByGitHubLogin(ctx context.Context, login string) (User, error) {
	return s.user(ctx, `u.github_login = ?`, login)
}

// user runs the shared SELECT. where is one of the fixed strings above,
// never caller input.
func (s *Store) user(ctx context.Context, where string, arg any) (User, error) {
	var (
		u        User
		login    sql.NullString
		disabled bool
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.name, u.github_login, u.is_admin, u.disabled_at IS NOT NULL
		FROM users u WHERE `+where+` ORDER BY u.id LIMIT 1`, arg).
		Scan(&u.ID, &u.Name, &login, &u.IsAdmin, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("look up user: %w", err)
	}
	u.GitHubLogin, u.Disabled = login.String, disabled
	return u, nil
}

// ListUsers returns every user, by name, with their key counts.
func (s *Store) ListUsers(ctx context.Context) ([]UserSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT u.id, u.name, u.github_login, u.is_admin, u.disabled_at IS NOT NULL,
		       (SELECT COUNT(*) FROM keys k WHERE k.user_id = u.id)
		FROM users u ORDER BY u.name`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []UserSummary
	for rows.Next() {
		var (
			u     UserSummary
			login sql.NullString
		)
		if err := rows.Scan(&u.ID, &u.Name, &login, &u.IsAdmin, &u.Disabled, &u.Keys); err != nil {
			return nil, fmt.Errorf("list users: %w", err)
		}
		u.GitHubLogin = login.String
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return out, nil
}

// KeysForUser returns the user's keys, oldest first.
func (s *Store) KeysForUser(ctx context.Context, userID int64) ([]Key, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, fingerprint_sha256, public_key, key_type, source, COALESCE(last_used_at, '')
		FROM keys WHERE user_id = ? ORDER BY id`, userID)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Key
	for rows.Next() {
		var k Key
		if err := rows.Scan(&k.ID, &k.UserID, &k.Fingerprint, &k.PublicKey, &k.KeyType, &k.Source, &k.LastUsedAt); err != nil {
			return nil, fmt.Errorf("list keys: %w", err)
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}
	return out, nil
}

// AddKeys registers keys for a user and returns the fingerprints it added.
// Keys the user already has are skipped. If any key is registered to
// another user, nothing is added and the error is ErrKeyInUse.
func (s *Store) AddKeys(ctx context.Context, userID int64, keys []NewKey) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("add keys: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	have, err := userFingerprints(ctx, tx, userID, "")
	if err != nil {
		return nil, err
	}
	var fresh []NewKey
	for _, k := range keys {
		if !slices.Contains(have, k.Fingerprint) {
			fresh = append(fresh, k)
			have = append(have, k.Fingerprint)
		}
	}
	if err := keysFree(ctx, tx, fresh); err != nil {
		return nil, err
	}
	if err := insertKeys(ctx, tx, userID, fresh, s.timestamp()); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("add keys: %w", err)
	}
	return fingerprints(fresh), nil
}

// RemoveKey deletes one of the user's keys. It fails with ErrNotFound if
// the user has no such key, and with ErrLastKey if it is their only one.
func (s *Store) RemoveKey(ctx context.Context, userID int64, fingerprint string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("remove key: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	have, err := userFingerprints(ctx, tx, userID, "")
	if err != nil {
		return err
	}
	if !slices.Contains(have, fingerprint) {
		return ErrNotFound
	}
	if len(have) == 1 {
		return ErrLastKey
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM keys WHERE user_id = ? AND fingerprint_sha256 = ?`, userID, fingerprint); err != nil {
		return fmt.Errorf("remove key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("remove key: %w", err)
	}
	return nil
}

// ReplaceGitHubKeys makes keys the user's complete set of GitHub-sourced
// keys: ones not in it are removed and new ones added. Manually added keys
// are kept. keys must not be empty. If a new key is registered to another
// user, nothing changes and the error is ErrKeyInUse.
func (s *Store) ReplaceGitHubKeys(ctx context.Context, userID int64, keys []NewKey) (KeyChanges, error) {
	if len(keys) == 0 {
		return KeyChanges{}, errors.New("replace keys: no keys given")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return KeyChanges{}, fmt.Errorf("replace keys: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	all, err := userFingerprints(ctx, tx, userID, "")
	if err != nil {
		return KeyChanges{}, err
	}
	fromGitHub, err := userFingerprints(ctx, tx, userID, SourceGitHub)
	if err != nil {
		return KeyChanges{}, err
	}
	want := fingerprints(keys)
	var ch KeyChanges
	for _, fp := range fromGitHub {
		if !slices.Contains(want, fp) {
			ch.Removed = append(ch.Removed, fp)
		}
	}
	// A key the user already has, from any source, is left as it is.
	var fresh []NewKey
	for _, k := range keys {
		if !slices.Contains(all, k.Fingerprint) {
			fresh = append(fresh, k)
		}
	}
	if err := keysFree(ctx, tx, fresh); err != nil {
		return KeyChanges{}, err
	}
	for _, fp := range ch.Removed {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM keys WHERE user_id = ? AND fingerprint_sha256 = ?`, userID, fp); err != nil {
			return KeyChanges{}, fmt.Errorf("replace keys: %w", err)
		}
	}
	if err := insertKeys(ctx, tx, userID, fresh, s.timestamp()); err != nil {
		return KeyChanges{}, err
	}
	if err := tx.Commit(); err != nil {
		return KeyChanges{}, fmt.Errorf("replace keys: %w", err)
	}
	ch.Added = fingerprints(fresh)
	return ch, nil
}

// userFingerprints returns the fingerprints of the user's keys, from one
// source or (if source is "") all of them.
func userFingerprints(ctx context.Context, tx *sql.Tx, userID int64, source string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT fingerprint_sha256 FROM keys WHERE user_id = ? AND (? = '' OR source = ?) ORDER BY id`,
		userID, source, source)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, fmt.Errorf("list keys: %w", err)
		}
		out = append(out, fp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}
	return out, nil
}

// keysFree fails with ErrKeyInUse if any of keys is registered to anyone.
func keysFree(ctx context.Context, tx *sql.Tx, keys []NewKey) error {
	for _, k := range keys {
		var taken bool
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM keys WHERE fingerprint_sha256 = ?)`, k.Fingerprint).Scan(&taken); err != nil {
			return fmt.Errorf("check key: %w", err)
		}
		if taken {
			return fmt.Errorf("%w: %s", ErrKeyInUse, k.Fingerprint)
		}
	}
	return nil
}

func insertKeys(ctx context.Context, tx *sql.Tx, userID int64, keys []NewKey, now string) error {
	for _, k := range keys {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO keys (user_id, fingerprint_sha256, public_key, key_type, source, added_at) VALUES (?, ?, ?, ?, ?, ?)`,
			userID, k.Fingerprint, k.PublicKey, k.KeyType, k.Source, now); err != nil {
			return fmt.Errorf("add key %s: %w", k.Fingerprint, err)
		}
	}
	return nil
}

func fingerprints(keys []NewKey) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.Fingerprint)
	}
	return out
}
