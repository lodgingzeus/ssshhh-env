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
)

const usage = `usage: ssshhh-env <command> [flags]

commands:
  serve           run the SSH server
  admin           server-side account management (run on the host)
  keygen-master   generate a 32-byte master key
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
	case "admin", "keygen-master":
		fmt.Fprintf(stderr, "ssshhh-env: %s: not implemented yet\n", args[0])
		return 1
	default:
		fmt.Fprintf(stderr, "ssshhh-env: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func serve(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", ":2222", "address to listen on")
	dataDir := fs.String("data-dir", "data", "directory for the host key and data (mode 0700)")
	allowPath := fs.String("authorized-keys", "", "allowed client keys, one \"<type> <key> <name>\" per line (default <data-dir>/authorized_keys)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("serve: unexpected argument %q", fs.Arg(0))
	}
	if *allowPath == "" {
		*allowPath = filepath.Join(*dataDir, "authorized_keys")
	}

	log := slog.New(slog.NewTextHandler(stderr, nil))

	if err := ensurePrivateDir(*dataDir); err != nil {
		return err
	}
	signer, created, err := server.LoadOrCreateHostKey(filepath.Join(*dataDir, "host_ed25519"))
	if err != nil {
		return err
	}
	allow, err := auth.LoadAllowlist(*allowPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w\n\nCreate it with your public key and a name, e.g.:\n  echo \"$(cut -d' ' -f1,2 ~/.ssh/id_ed25519.pub) $USER\" > %s && chmod 600 %s", err, *allowPath, *allowPath)
		}
		return err
	}
	if allow.Len() == 0 {
		return fmt.Errorf("%s has no keys", *allowPath)
	}

	cfg := server.DefaultConfig()
	cfg.Addr = *addr
	cfg.HostSigner = signer
	cfg.Allowlist = allow
	cfg.Logger = log
	srv, err := server.New(cfg)
	if err != nil {
		return err
	}

	if created {
		log.Info("generated new host key")
	}
	log.Info("starting", "addr", *addr, "host_key", auth.Fingerprint(signer.PublicKey()), "allowed_keys", allow.Len())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
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
