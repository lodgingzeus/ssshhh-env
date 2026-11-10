package store

import (
	"context"
	"fmt"
)

// ConfirmMasterKeyBackup records that the operator has backed up the master
// key with this id. Confirming again keeps the first confirmation time.
func (s *Store) ConfirmMasterKeyBackup(ctx context.Context, keyID string) error {
	if keyID == "" {
		return fmt.Errorf("confirm backup: key id required")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO master_key_backups (key_id, confirmed_at) VALUES (?, ?) ON CONFLICT (key_id) DO NOTHING`,
		keyID, s.timestamp())
	if err != nil {
		return fmt.Errorf("confirm backup: %w", err)
	}
	return nil
}

// MasterKeyBackupConfirmed reports whether a backup of the master key with
// this id has been confirmed.
func (s *Store) MasterKeyBackupConfirmed(ctx context.Context, keyID string) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM master_key_backups WHERE key_id = ?`, keyID).Scan(&n); err != nil {
		return false, fmt.Errorf("read backup confirmation: %w", err)
	}
	return n > 0, nil
}
