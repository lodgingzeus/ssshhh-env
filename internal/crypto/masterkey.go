package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// keyIDPrefix separates key-id hashing from any other use of SHA-256.
const keyIDPrefix = "ssshhh-env:master-key-id:v1\x00"

// maxKeyFile caps how much of a master key file is read. An encoded key is
// 44 bytes; anything much larger is the wrong file.
const maxKeyFile = 1024

// MasterKey is the key-encryption key. It wraps project DEKs and is never
// stored in the database.
type MasterKey struct {
	key [KeySize]byte
	id  string
}

// GenerateMasterKey returns a new random master key.
func GenerateMasterKey() (*MasterKey, error) {
	var key [KeySize]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, fmt.Errorf("crypto: generate master key: %w", err)
	}
	return newMasterKey(key), nil
}

func newMasterKey(key [KeySize]byte) *MasterKey {
	sum := sha256.Sum256(append([]byte(keyIDPrefix), key[:]...))
	return &MasterKey{key: key, id: hex.EncodeToString(sum[:8])}
}

// ParseMasterKey decodes a key in the form Encode produces: 32 bytes in
// standard base64. Surrounding whitespace is ignored. Errors never include
// the input.
func ParseMasterKey(encoded string) (*MasterKey, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, errors.New("master key is not valid base64 (generate one with: ssshhh-env keygen-master)")
	}
	if len(raw) != KeySize {
		return nil, fmt.Errorf("master key is %d bytes, want %d", len(raw), KeySize)
	}
	var key [KeySize]byte
	copy(key[:], raw)
	if key == ([KeySize]byte{}) {
		return nil, errors.New("master key is all zeros")
	}
	return newMasterKey(key), nil
}

// LoadMasterKeyFile reads a master key from path. The file must be a
// regular file that group and others cannot access.
func LoadMasterKeyFile(path string) (*MasterKey, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied path from a CLI flag
	if err != nil {
		return nil, fmt.Errorf("master key file: %w", err)
	}
	defer func() { _ = f.Close() }()
	// Checked on the open file, not the path, so the file that is checked
	// is the file that is read.
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("master key file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("master key file %s is not a regular file", path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("master key file %s: mode %04o is too open, want 0600 (chmod 600 %s)", path, perm, path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, fmt.Errorf("master key file: %w", err)
	}
	if len(data) > maxKeyFile {
		return nil, fmt.Errorf("master key file %s is too large to be a master key", path)
	}
	k, err := ParseMasterKey(string(data))
	if err != nil {
		return nil, fmt.Errorf("master key file %s: %w", path, err)
	}
	return k, nil
}

// Encode returns the key as base64. The result is the secret itself: write
// it only to the key file or to the operator's terminal.
func (k *MasterKey) Encode() string {
	return base64.StdEncoding.EncodeToString(k.key[:])
}

// ID identifies the key without revealing it. It is stored next to each
// wrapped DEK, so a wrong master key is reported as such.
func (k *MasterKey) ID() string { return k.id }

// String and GoString keep the key out of logs and error messages if a
// MasterKey is ever formatted by mistake.
func (k *MasterKey) String() string   { return "MasterKey(" + k.id + ")" }
func (k *MasterKey) GoString() string { return k.String() }
