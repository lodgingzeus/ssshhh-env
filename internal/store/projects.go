package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrExists is returned when a row with the same unique name already exists.
var ErrExists = errors.New("already exists")

// Project is a named set of environments sharing one data key. The key is
// held only in wrapped form.
type Project struct {
	ID          int64
	Name        string
	WrappedDEK  []byte
	DEKNonce    []byte
	MasterKeyID string
}

// WrappedDEK is a project's data key, encrypted under a master key.
type WrappedDEK struct {
	Nonce       []byte
	Ciphertext  []byte
	MasterKeyID string
}

// CreateProject creates a project and makes creatorID its owner, atomically.
// It fails with ErrExists if the name is taken.
//
// wrap is called inside the transaction with the id the project will have,
// because the data key is bound to that id when it is wrapped.
func (s *Store) CreateProject(ctx context.Context, name string, creatorID int64, wrap func(projectID int64) (WrappedDEK, error)) (Project, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Project{}, fmt.Errorf("create project: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM projects WHERE name = ?)`, name).Scan(&exists); err != nil {
		return Project{}, fmt.Errorf("create project: %w", err)
	}
	if exists {
		return Project{}, ErrExists
	}
	// The transaction holds the write lock from BEGIN, so nothing else can
	// take this id before the insert below.
	var id int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) + 1 FROM projects`).Scan(&id); err != nil {
		return Project{}, fmt.Errorf("create project: %w", err)
	}
	dek, err := wrap(id)
	if err != nil {
		return Project{}, fmt.Errorf("create project: wrap data key: %w", err)
	}
	if len(dek.Nonce) == 0 || len(dek.Ciphertext) == 0 || dek.MasterKeyID == "" {
		return Project{}, errors.New("create project: incomplete wrapped data key")
	}

	now := s.timestamp()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO projects (id, name, wrapped_dek, dek_nonce, master_key_id, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, name, dek.Ciphertext, dek.Nonce, dek.MasterKeyID, creatorID, now); err != nil {
		return Project{}, fmt.Errorf("create project: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO members (project_id, user_id, role, granted_by, granted_at) VALUES (?, ?, ?, ?, ?)`,
		id, creatorID, RoleOwner, creatorID, now); err != nil {
		return Project{}, fmt.Errorf("create project: add owner: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Project{}, fmt.Errorf("create project: %w", err)
	}
	return Project{ID: id, Name: name, WrappedDEK: dek.Ciphertext, DEKNonce: dek.Nonce, MasterKeyID: dek.MasterKeyID}, nil
}

// ProjectByName returns the project called name, or ErrNotFound.
func (s *Store) ProjectByName(ctx context.Context, name string) (Project, error) {
	p := Project{Name: name}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, wrapped_dek, dek_nonce, master_key_id FROM projects WHERE name = ?`, name).
		Scan(&p.ID, &p.WrappedDEK, &p.DEKNonce, &p.MasterKeyID)
	if errors.Is(err, sql.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	if err != nil {
		return Project{}, fmt.Errorf("look up project: %w", err)
	}
	return p, nil
}

// MasterKeyIDs returns the ids of the master keys that projects' data keys
// are wrapped with. More than one, or one the server doesn't hold, means
// some projects cannot be decrypted.
func (s *Store) MasterKeyIDs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT master_key_id FROM projects ORDER BY master_key_id`)
	if err != nil {
		return nil, fmt.Errorf("list master key ids: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("list master key ids: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list master key ids: %w", err)
	}
	return ids, nil
}
