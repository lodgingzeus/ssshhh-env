package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"

	gossh "golang.org/x/crypto/ssh"
)

// LoadOrCreateHostKey loads the ed25519 host key at path, generating it on
// first run. The file must be mode 0600 or stricter. created reports whether
// a new key was written.
func LoadOrCreateHostKey(path string) (signer gossh.Signer, created bool, err error) {
	data, err := readPrivateFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		data, err = createHostKey(path)
		created = true
	}
	if err != nil {
		return nil, false, err
	}
	signer, err = gossh.ParsePrivateKey(data)
	if err != nil {
		return nil, false, fmt.Errorf("host key %s: %w", path, err)
	}
	if signer.PublicKey().Type() != gossh.KeyAlgoED25519 {
		return nil, false, fmt.Errorf("host key %s: want ed25519, got %s", path, signer.PublicKey().Type())
	}
	return signer, created, nil
}

func readPrivateFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s: mode %04o is too open, want 0600", path, perm)
	}
	return os.ReadFile(path) // #nosec G304 -- operator-supplied path from a CLI flag
}

func createHostKey(path string) ([]byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}
	block, err := gossh.MarshalPrivateKey(priv, "ssshhh-env host key")
	if err != nil {
		return nil, fmt.Errorf("marshal host key: %w", err)
	}
	data := pem.EncodeToMemory(block)

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator-supplied path from a CLI flag
	if err != nil {
		return nil, fmt.Errorf("create host key: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("write host key: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("write host key: %w", err)
	}
	return data, nil
}
