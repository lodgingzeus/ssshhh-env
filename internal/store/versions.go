package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// Version is one stored revision of an environment's .env file. The store
// only ever sees it encrypted.
type Version struct {
	EnvID      int64
	Number     int64 // 1, 2, 3, ... within the environment
	Nonce      []byte
	Ciphertext []byte
	SizeBytes  int64 // size of the plaintext
	KeyNames   []string
	AuthorID   int64
	Message    string
	CreatedAt  string
}

// NewVersion describes a version to append. It carries no plaintext.
type NewVersion struct {
	ProjectID int64
	EnvName   string
	AuthorID  int64
	Message   string
	KeyNames  []string // variable names only
	SizeBytes int64
}

// SealedVersion is the encrypted payload of a version.
type SealedVersion struct {
	Nonce      []byte
	Ciphertext []byte
}

// AppendVersion adds the next version to an environment, creating the
// environment on its first push. Versions are numbered 1, 2, 3, ... and are
// never changed or removed afterwards.
//
// seal is called inside the transaction with the row ids the version will
// have, because the ciphertext is bound to them when it is sealed.
func (s *Store) AppendVersion(ctx context.Context, v NewVersion, seal func(envID, number int64) (SealedVersion, error)) (Version, error) {
	names := v.KeyNames
	if names == nil {
		names = []string{}
	}
	namesJSON, err := json.Marshal(names)
	if err != nil {
		return Version{}, fmt.Errorf("append version: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Version{}, fmt.Errorf("append version: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := s.timestamp()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO environments (project_id, name, created_at) VALUES (?, ?, ?)
		ON CONFLICT (project_id, name) DO NOTHING`, v.ProjectID, v.EnvName, now); err != nil {
		return Version{}, fmt.Errorf("append version: create environment: %w", err)
	}
	out := Version{SizeBytes: v.SizeBytes, KeyNames: names, AuthorID: v.AuthorID, Message: v.Message, CreatedAt: now}
	if err := tx.QueryRowContext(ctx,
		`SELECT id FROM environments WHERE project_id = ? AND name = ?`, v.ProjectID, v.EnvName).Scan(&out.EnvID); err != nil {
		return Version{}, fmt.Errorf("append version: %w", err)
	}
	// The transaction holds the write lock from BEGIN, so two pushes can't
	// both get the same number.
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version), 0) + 1 FROM versions WHERE env_id = ?`, out.EnvID).Scan(&out.Number); err != nil {
		return Version{}, fmt.Errorf("append version: %w", err)
	}

	sealed, err := seal(out.EnvID, out.Number)
	if err != nil {
		return Version{}, fmt.Errorf("append version: seal: %w", err)
	}
	if len(sealed.Nonce) == 0 || len(sealed.Ciphertext) == 0 {
		return Version{}, errors.New("append version: incomplete sealed payload")
	}
	out.Nonce, out.Ciphertext = sealed.Nonce, sealed.Ciphertext

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO versions (env_id, version, nonce, ciphertext, size_bytes, key_names_json, author_id, message, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		out.EnvID, out.Number, out.Nonce, out.Ciphertext, out.SizeBytes, string(namesJSON), out.AuthorID, out.Message, now); err != nil {
		return Version{}, fmt.Errorf("append version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Version{}, fmt.Errorf("append version: %w", err)
	}
	return out, nil
}

// LatestVersion returns the newest version of the environment, or
// ErrNotFound if the environment does not exist.
func (s *Store) LatestVersion(ctx context.Context, projectID int64, envName string) (Version, error) {
	return s.version(ctx, `ORDER BY v.version DESC LIMIT 1`, projectID, envName)
}

// VersionByNumber returns one version of the environment, or ErrNotFound.
func (s *Store) VersionByNumber(ctx context.Context, projectID int64, envName string, number int64) (Version, error) {
	return s.version(ctx, `AND v.version = ?`, projectID, envName, number)
}

// version runs the shared SELECT. suffix is one of the fixed strings above,
// never caller input.
func (s *Store) version(ctx context.Context, suffix string, args ...any) (Version, error) {
	var (
		v         Version
		namesJSON string
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT v.env_id, v.version, v.nonce, v.ciphertext, v.size_bytes, v.key_names_json, v.author_id, v.message, v.created_at
		FROM versions v JOIN environments e ON e.id = v.env_id
		WHERE e.project_id = ? AND e.name = ? `+suffix, args...).Scan(
		&v.EnvID, &v.Number, &v.Nonce, &v.Ciphertext, &v.SizeBytes, &namesJSON, &v.AuthorID, &v.Message, &v.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Version{}, ErrNotFound
	}
	if err != nil {
		return Version{}, fmt.Errorf("read version: %w", err)
	}
	if err := json.Unmarshal([]byte(namesJSON), &v.KeyNames); err != nil {
		return Version{}, fmt.Errorf("read version: key names: %w", err)
	}
	return v, nil
}
