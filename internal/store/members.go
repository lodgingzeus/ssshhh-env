package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Member roles, as stored in members.role.
const (
	RoleOwner  = "owner"
	RoleWriter = "writer"
	RoleReader = "reader"
)

// ErrLastOwner is returned when a change would leave a project with no
// owner: nobody could grant or revoke access to it any more.
var ErrLastOwner = errors.New("project would have no owner")

// Member is one user's membership of a project.
type Member struct {
	UserID    int64
	Name      string
	Role      string
	Disabled  bool
	GrantedBy string // name of the user who granted the role
	GrantedAt string
}

// Membership is a project the user belongs to, with their role and the
// project's environments.
type Membership struct {
	Project string
	Role    string
	Envs    []string // sorted; empty until the first push
}

// roleOrder sorts owners first, then writers, then readers.
const roleOrder = `CASE m.role WHEN 'owner' THEN 0 WHEN 'writer' THEN 1 ELSE 2 END`

// AddMember gives a user a role in a project. It fails with ErrExists if
// they are already a member; changing a role is SetMemberRole.
func (s *Store) AddMember(ctx context.Context, projectID, userID int64, role string, grantedBy int64) error {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO members (project_id, user_id, role, granted_by, granted_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (project_id, user_id) DO NOTHING`,
		projectID, userID, role, grantedBy, s.timestamp())
	if err != nil {
		return fmt.Errorf("add member: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrExists
	}
	return nil
}

// MemberRole returns the user's role in the project, or ErrNotFound if they
// are not a member.
func (s *Store) MemberRole(ctx context.Context, projectID, userID int64) (string, error) {
	var role string
	err := s.db.QueryRowContext(ctx,
		`SELECT role FROM members WHERE project_id = ? AND user_id = ?`, projectID, userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("look up member: %w", err)
	}
	return role, nil
}

// SetMemberRole changes an existing member's role and records who changed
// it. It fails with ErrNotFound if the user is not a member, and with
// ErrLastOwner if it would demote the project's only owner.
func (s *Store) SetMemberRole(ctx context.Context, projectID, userID int64, role string, grantedBy int64) error {
	return s.changeMember(ctx, "set member role", projectID, userID, role != RoleOwner, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE members SET role = ?, granted_by = ?, granted_at = ? WHERE project_id = ? AND user_id = ?`,
			role, grantedBy, s.timestamp(), projectID, userID)
		return err
	})
}

// RemoveMember takes a user's access to a project away. It fails with
// ErrNotFound if they are not a member, and with ErrLastOwner if they are
// the project's only owner.
func (s *Store) RemoveMember(ctx context.Context, projectID, userID int64) error {
	return s.changeMember(ctx, "remove member", projectID, userID, true, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM members WHERE project_id = ? AND user_id = ?`, projectID, userID)
		return err
	})
}

// changeMember runs change in a write transaction after checking that the
// member exists and, if losesOwner, that they are not the last owner. The
// check and the change share the transaction, so two owners revoking each
// other at the same moment can't both succeed.
func (s *Store) changeMember(ctx context.Context, what string, projectID, userID int64, losesOwner bool, change func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	defer func() { _ = tx.Rollback() }()

	var role string
	err = tx.QueryRowContext(ctx, `SELECT role FROM members WHERE project_id = ? AND user_id = ?`, projectID, userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if losesOwner && role == RoleOwner {
		var owners int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM members WHERE project_id = ? AND role = ?`, projectID, RoleOwner).Scan(&owners); err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		if owners <= 1 {
			return ErrLastOwner
		}
	}
	if err := change(tx); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	return nil
}

// ListMembers returns the project's members, owners first, then by name.
func (s *Store) ListMembers(ctx context.Context, projectID int64) ([]Member, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT m.user_id, u.name, m.role, u.disabled_at IS NOT NULL, g.name, m.granted_at
		FROM members m
		JOIN users u ON u.id = m.user_id
		JOIN users g ON g.id = m.granted_by
		WHERE m.project_id = ?
		ORDER BY `+roleOrder+`, u.name`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.UserID, &m.Name, &m.Role, &m.Disabled, &m.GrantedBy, &m.GrantedAt); err != nil {
			return nil, fmt.Errorf("list members: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	return out, nil
}

// ProjectsForUser returns the projects the user is a member of, by name.
func (s *Store) ProjectsForUser(ctx context.Context, userID int64) ([]Membership, error) {
	// Environment names are joined with ',' which a valid name can't contain.
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.name, m.role,
		       COALESCE((SELECT group_concat(e.name, ',') FROM environments e WHERE e.project_id = p.id), '')
		FROM members m JOIN projects p ON p.id = m.project_id
		WHERE m.user_id = ?
		ORDER BY p.name`, userID)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Membership
	for rows.Next() {
		var (
			m    Membership
			envs string
		)
		if err := rows.Scan(&m.Project, &m.Role, &envs); err != nil {
			return nil, fmt.Errorf("list projects: %w", err)
		}
		if envs != "" {
			m.Envs = strings.Split(envs, ",")
			slices.Sort(m.Envs) // group_concat's order is unspecified
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	return out, nil
}

// EnvironmentNames returns the names of the project's environments, sorted.
func (s *Store) EnvironmentNames(ctx context.Context, projectID int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM environments WHERE project_id = ? ORDER BY name`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list environments: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("list environments: %w", err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list environments: %w", err)
	}
	return out, nil
}
