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
	"strings"
	"syscall"
	"time"

	"charm.land/ssh"
	gossh "golang.org/x/crypto/ssh"

	"github.com/lodgingzeus/ssshhh-env/internal/audit"
	"github.com/lodgingzeus/ssshhh-env/internal/auth"
	"github.com/lodgingzeus/ssshhh-env/internal/github"
	"github.com/lodgingzeus/ssshhh-env/internal/server"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
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
	case "admin":
		if err := admin(args[1:], stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "ssshhh-env: %v\n", err)
			return 1
		}
		return 0
	case "keygen-master":
		fmt.Fprintf(stderr, "ssshhh-env: %s: not implemented yet\n", args[0])
		return 1
	default:
		fmt.Fprintf(stderr, "ssshhh-env: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// dbName is the database file inside the data directory.
const dbName = "ssshhh.db"

// githubClient is replaced in tests.
var githubClient = github.Client{}

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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("serve: unexpected argument %q", fs.Arg(0))
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
	signer, created, err := server.LoadOrCreateHostKey(filepath.Join(dir, "host_ed25519"))
	if err != nil {
		return err
	}

	cfg := server.DefaultConfig()
	cfg.Addr = *addr
	cfg.HostSigner = signer
	cfg.Store = st
	cfg.Logger = log
	srv, err := server.New(cfg)
	if err != nil {
		return err
	}

	if created {
		log.Info("generated new host key")
	}
	log.Info("starting", "addr", *addr, "host_key", auth.Fingerprint(signer.PublicKey()), "data_dir", dir, "users", users)

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

const adminUsage = `usage: ssshhh-env admin <command> [flags]

commands:
  bootstrap   create the first admin user (only works while there are no users)
`

func admin(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("admin: command required\n\n" + strings.TrimSpace(adminUsage))
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, adminUsage)
		return nil
	case "bootstrap":
		return bootstrap(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("admin: unknown command %q\n\n%s", args[0], strings.TrimSpace(adminUsage))
	}
}

// maxKeyFile caps how much of a --key file is read.
const maxKeyFile = 64 << 10

// bootstrap creates the first admin. It runs on the host, against the data
// directory, so nobody can claim admin over the network.
func bootstrap(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("admin bootstrap", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", "data", "directory for the database and host key (mode 0700)")
	keyPath := fs.String("key", "", "public key file, e.g. ~/.ssh/id_ed25519.pub")
	login := fs.String("github", "", "GitHub username to fetch public keys from")
	name := fs.String("name", "", "user name (default: the GitHub username)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("admin bootstrap: unexpected argument %q", fs.Arg(0))
	}
	if (*keyPath == "") == (*login == "") {
		return errors.New("admin bootstrap: give exactly one of --key or --github")
	}
	if *login != "" && !github.ValidLogin(*login) {
		return errors.New("admin bootstrap: invalid GitHub username")
	}
	if *name == "" {
		if *login == "" {
			return errors.New("admin bootstrap: --name is required with --key")
		}
		*name = *login
	}
	if !auth.ValidName(*name) {
		return errors.New("admin bootstrap: name must be 1-64 characters: letters, digits, '.', '_' or '-', starting with a letter or digit")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, dir, err := openData(ctx, *dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	// Checked again inside the transaction; this is to fail before any
	// network request.
	if n, err := st.CountUsers(ctx); err != nil {
		return err
	} else if n > 0 {
		return errAlreadyBootstrapped(dir)
	}

	var (
		pubs   []gossh.PublicKey
		source = store.SourceManual
	)
	if *login != "" {
		source = store.SourceGitHub
		pubs, err = githubClient.Keys(ctx, *login)
		if err != nil {
			return err
		}
	} else {
		pubs, err = readKeyFile(*keyPath)
		if err != nil {
			return err
		}
	}

	var keys []store.NewKey
	for _, pub := range pubs {
		k, err := auth.NewKey(pub, source)
		if err != nil {
			fmt.Fprintf(stderr, "skipping %s %s: %v\n", pub.Type(), auth.Fingerprint(pub), err)
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return errors.New("admin bootstrap: no acceptable keys (allowed: ed25519, ECDSA, FIDO sk-*, RSA of 3072 bits or more)")
	}

	u, err := st.BootstrapAdmin(ctx, *name, *login, keys)
	if errors.Is(err, store.ErrAlreadyBootstrapped) {
		return errAlreadyBootstrapped(dir)
	}
	if err != nil {
		return err
	}
	if err := audit.Log(ctx, st, audit.Event{
		UserID:     u.ID,
		RemoteAddr: "local",
		Action:     "bootstrap",
		Result:     audit.OK,
		Detail:     fmt.Sprintf("first admin created with %d key(s) from %s", len(keys), source),
	}); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "Created admin %q in %s with these keys:\n", u.Name, dir)
	for _, k := range keys {
		fmt.Fprintf(stdout, "  %s  %s\n", k.Fingerprint, k.KeyType)
	}
	if source == store.SourceGitHub {
		fmt.Fprintf(stdout, "\nThe keys were fetched from GitHub once and are now pinned. Check the\nfingerprints above against your own: ssh-keygen -lf ~/.ssh/id_ed25519.pub\n")
	}
	return nil
}

func errAlreadyBootstrapped(dir string) error {
	return fmt.Errorf("admin bootstrap: %s already has users; bootstrap only creates the first one", dir)
}

func readKeyFile(path string) ([]gossh.PublicKey, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied path from a CLI flag
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxKeyFile {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, maxKeyFile)
	}
	pubs, err := auth.ParsePublicKeys(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (expected a .pub file)", path, err)
	}
	if len(pubs) == 0 {
		return nil, fmt.Errorf("%s: no public keys found", path)
	}
	return pubs, nil
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
