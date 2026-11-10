package store

import (
	"context"
	"database/sql"
	"fmt"
)

// AuditRow is one audit_log entry. Use the audit package to write them: it
// validates and sanitises the fields.
type AuditRow struct {
	ID             int64
	Time           string // UTC, set by the store on insert
	UserID         int64  // 0 if the actor is not a known user
	KeyFingerprint string
	RemoteAddr     string
	Action         string
	Target         string
	Result         string
	Detail         string
}

// InsertAudit appends a row to the audit log. There is deliberately no way
// to update or delete one.
func (s *Store) InsertAudit(ctx context.Context, r AuditRow) error {
	var userID any
	if r.UserID != 0 {
		userID = r.UserID
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_log (ts, user_id, key_fingerprint, remote_addr, action, target, result, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		s.timestamp(), userID, nullable(r.KeyFingerprint), r.RemoteAddr, r.Action, r.Target, r.Result, r.Detail)
	if err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	return nil
}

// ListAudit returns the most recent audit rows, newest first.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, ts, user_id, key_fingerprint, remote_addr, action, target, result, detail
		FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AuditRow
	for rows.Next() {
		var (
			r      AuditRow
			userID sql.NullInt64
			fp     sql.NullString
		)
		if err := rows.Scan(&r.ID, &r.Time, &userID, &fp, &r.RemoteAddr, &r.Action, &r.Target, &r.Result, &r.Detail); err != nil {
			return nil, fmt.Errorf("read audit log: %w", err)
		}
		r.UserID = userID.Int64
		r.KeyFingerprint = fp.String
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	return out, nil
}
