package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	gossh "golang.org/x/crypto/ssh"

	"github.com/lodgingzeus/ssshhh-env/internal/audit"
	"github.com/lodgingzeus/ssshhh-env/internal/auth"
	"github.com/lodgingzeus/ssshhh-env/internal/github"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// githubClient is replaced in tests.
var githubClient = github.Client{}

const adminUsage = `usage: ssshhh-env admin <command> [flags]

commands:
  bootstrap        create the first admin user (only works while there are no users)
  confirm-backup   record that the master key is backed up (stops the startup warning)
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
	case "confirm-backup":
		return confirmBackup(args[1:], stdout, stderr)
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
