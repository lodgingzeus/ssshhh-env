package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/lodgingzeus/ssshhh-env/internal/crypto"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// masterKeyEnv is the environment variable that can hold the master key
// instead of a file.
const masterKeyEnv = "SSSHHH_MASTER_KEY"

const masterKeyAdvice = `Keep this key safe:
  - Anyone who has it and the database can read every secret.
  - If you lose it, everything in the database is unrecoverable.
  - Back it up somewhere separate from the database. A backup that holds
    both is as good as unencrypted.
`

// keygenMaster generates a master key. With --out it writes a new 0600
// file; otherwise it prints the key to stdout.
func keygenMaster(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("keygen-master", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "write the key to this new file with mode 0600 (default: print to stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("keygen-master: unexpected argument %q", fs.Arg(0))
	}
	key, err := crypto.GenerateMasterKey()
	if err != nil {
		return err
	}

	if *out == "" {
		if _, err := fmt.Fprintln(stdout, key.Encode()); err != nil {
			return err
		}
		fmt.Fprintf(stderr, "Generated master key %s.\nIf you save it to a file, make the file private: chmod 600 <file>\n\n%s", key.ID(), masterKeyAdvice)
		return nil
	}
	if err := writeNewKeyFile(*out, key.Encode()+"\n"); err != nil {
		return fmt.Errorf("keygen-master: %w", err)
	}
	fmt.Fprintf(stderr, "Wrote master key %s to %s (mode 0600).\n\n%s", key.ID(), *out, masterKeyAdvice)
	return nil
}

// writeNewKeyFile creates path with mode 0600. It never overwrites: an
// existing file may be the only copy of a key that data depends on.
func writeNewKeyFile(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator-supplied path from a CLI flag
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s already exists; refusing to overwrite it", path)
	}
	if err != nil {
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// loadMasterKey reads the master key from keyFile or, if that is empty,
// from the environment. Exactly one source must be set: guessing between
// two keys could encrypt new data under the wrong one.
func loadMasterKey(keyFile string) (*crypto.MasterKey, error) {
	fromEnv, envSet := os.LookupEnv(masterKeyEnv)
	switch {
	case keyFile != "" && envSet:
		return nil, fmt.Errorf("both --master-key-file and %s are set; use only one", masterKeyEnv)
	case keyFile != "":
		return crypto.LoadMasterKeyFile(keyFile)
	case envSet:
		// Nothing else needs it, so don't leave it in the environment.
		_ = os.Unsetenv(masterKeyEnv)
		key, err := crypto.ParseMasterKey(fromEnv)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", masterKeyEnv, err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("no master key. Generate one with:\n  ssshhh-env keygen-master --out master.key\nthen start the server with --master-key-file master.key (or set %s)", masterKeyEnv)
	}
}

// checkMasterKey refuses a master key that cannot decrypt the projects
// already in the database, so the mistake shows at startup and not as
// failing pulls later.
func checkMasterKey(ctx context.Context, st *store.Store, key *crypto.MasterKey) error {
	ids, err := st.MasterKeyIDs(ctx)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if id != key.ID() {
			return fmt.Errorf("wrong master key: the database has projects encrypted under key %s, but the key provided is %s", id, key.ID())
		}
	}
	return nil
}
