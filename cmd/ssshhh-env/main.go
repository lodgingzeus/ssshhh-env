// Command ssshhh-env is a self-hosted SSH server for sharing .env files.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"charm.land/ssh"

	"github.com/lodgingzeus/ssshhh-env/internal/auth"
	"github.com/lodgingzeus/ssshhh-env/internal/server"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

const usage = `usage: ssshhh-env <command> [flags]

commands:
  serve           run the SSH server
  admin           server-side account management (run on the host)
  keygen-master   generate the master key that encrypts the database
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "serve":
		if err := serve(args[1:], stderr); err != nil {
			fmt.Fprintf(stderr, "ssshhh-env: %v\n", err)
			return 1
		}
		return 0
	case "admin":
		if err := admin(args[1:], stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "ssshhh-env: %v\n", err)
			return 1
		}
		return 0
	case "keygen-master":
		if err := keygenMaster(args[1:], stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "ssshhh-env: %v\n", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "ssshhh-env: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// dbName is the database file inside the data directory.
const dbName = "ssshhh.db"

// openData checks the data directory and opens the database in it. The
// returned directory is absolute, so later messages name real paths.
func openData(ctx context.Context, dataDir string) (*store.Store, string, error) {
	dir, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, "", err
	}
	if err := ensurePrivateDir(dir); err != nil {
		return nil, "", err
	}
	st, err := store.Open(ctx, filepath.Join(dir, dbName))
	if err != nil {
		return nil, "", err
	}
	return st, dir, nil
}

func serve(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", ":2222", "address to listen on")
	dataDir := fs.String("data-dir", "data", "directory for the database and host key (mode 0700)")
	keyFile := fs.String("master-key-file", "", "master key file (mode 0600); or set "+masterKeyEnv)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("serve: unexpected argument %q", fs.Arg(0))
	}
	// Loaded first: without it nothing can be served, and a refused start
	// should leave nothing behind.
	masterKey, err := loadMasterKey(*keyFile)
	if err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, dir, err := openData(ctx, *dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	// Checked before the host key is created, so a refused start leaves no
	// key behind.
	users, err := st.CountUsers(ctx)
	if err != nil {
		return err
	}
	if users == 0 {
		return fmt.Errorf("no users yet. Create the first admin with:\n  ssshhh-env admin bootstrap --data-dir %s --name <you> --key ~/.ssh/id_ed25519.pub", dir)
	}
	if err := checkMasterKey(ctx, st, masterKey); err != nil {
		return err
	}
	signer, created, err := server.LoadOrCreateHostKey(filepath.Join(dir, "host_ed25519"))
	if err != nil {
		return err
	}

	cfg := server.DefaultConfig()
	cfg.Addr = *addr
	cfg.HostSigner = signer
	cfg.Store = st
	cfg.MasterKey = masterKey
	cfg.Logger = log
	srv, err := server.New(cfg)
	if err != nil {
		return err
	}

	if created {
		log.Info("generated new host key")
	}
	log.Info("starting", "addr", *addr, "host_key", auth.Fingerprint(signer.PublicKey()), "data_dir", dir, "users", users, "master_key_id", masterKey.ID())

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
		return err
	}
	return nil
}

// ensurePrivateDir creates dir with mode 0700, or checks that an existing
// one is not accessible to group or others.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%s: mode %04o is too open, want 0700 (chmod 700 %s)", dir, perm, dir)
	}
	return nil
}
