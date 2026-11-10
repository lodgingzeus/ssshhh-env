package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/lodgingzeus/ssshhh-env/internal/audit"
	"github.com/lodgingzeus/ssshhh-env/internal/crypto"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// confirmBackup records that the operator has backed up the master key, so
// serve stops warning about it. It checks the key against the database
// first: confirming a key the data isn't encrypted under would silence the
// warning for the wrong key.
func confirmBackup(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("admin confirm-backup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", "data", "directory for the database and host key (mode 0700)")
	keyFile := fs.String("master-key-file", "", "master key file (mode 0600); or set "+masterKeyEnv)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("admin confirm-backup: unexpected argument %q", fs.Arg(0))
	}
	key, err := loadMasterKey(*keyFile)
	if err != nil {
		return err
	}
	// Don't create a data directory or database as a side effect: there is
	// nothing to confirm before the server has been set up.
	if _, err := os.Stat(filepath.Join(*dataDir, dbName)); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("admin confirm-backup: no database in %s; run admin bootstrap first", *dataDir)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	st, dir, err := openData(ctx, *dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	if err := checkMasterKey(ctx, st, key); err != nil {
		return err
	}
	if err := st.ConfirmMasterKeyBackup(ctx, key.ID()); err != nil {
		return err
	}
	if err := audit.Log(ctx, st, audit.Event{
		RemoteAddr: "local",
		Action:     "confirm-backup",
		Target:     key.ID(),
		Result:     audit.OK,
		Detail:     "master key backup confirmed by the operator",
	}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Recorded that master key %s is backed up (%s).\nKeep that backup separate from backups of the database.\n", key.ID(), dir)
	return nil
}

// backupWarning returns a warning if the backup of key has not been
// confirmed, or "" if it has. It never stops the server from starting.
func backupWarning(ctx context.Context, st *store.Store, key *crypto.MasterKey, dataDir string) (string, error) {
	ok, err := st.MasterKeyBackupConfirmed(ctx, key.ID())
	if err != nil || ok {
		return "", err
	}
	return fmt.Sprintf("master key %s has no confirmed backup. If it is lost, every secret is unrecoverable. "+
		"Back it up separately from the database, then run: ssshhh-env admin confirm-backup --data-dir %s --master-key-file <file>",
		key.ID(), dataDir), nil
}
