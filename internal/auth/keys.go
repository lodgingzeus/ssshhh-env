package auth

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"regexp"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// Identity is an authenticated user and the key they used.
type Identity struct {
	UserID      int64
	KeyID       int64
	Name        string
	IsAdmin     bool
	Fingerprint string
	KeyType     string
}

var (
	// ErrUnknownKey means the key is not registered.
	ErrUnknownKey = errors.New("key not registered")
	// ErrUserDisabled means the key is registered to a disabled user.
	ErrUserDisabled = errors.New("user disabled")
)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidName reports whether name is an acceptable user name.
func ValidName(name string) bool { return nameRe.MatchString(name) }

// KeyStore looks up registered keys. *store.Store implements it.
type KeyStore interface {
	KeyByFingerprint(ctx context.Context, fingerprint string) (store.Key, store.User, error)
}

// Lookup returns the identity pub belongs to. It fails with ErrWeakKey,
// ErrUnknownKey or ErrUserDisabled; any other error is a storage failure.
// Every caller must treat every error as "not authenticated".
func Lookup(ctx context.Context, ks KeyStore, pub gossh.PublicKey) (Identity, error) {
	if pub == nil {
		return Identity{}, ErrUnknownKey
	}
	// Checked on every lookup, so a tightened policy also applies to keys
	// registered before it changed.
	if err := CheckKeyPolicy(pub); err != nil {
		return Identity{}, err
	}
	k, u, err := ks.KeyByFingerprint(ctx, Fingerprint(pub))
	if errors.Is(err, store.ErrNotFound) {
		return Identity{}, ErrUnknownKey
	}
	if err != nil {
		return Identity{}, err
	}
	// The fingerprint found the row; the full key must match too.
	if subtle.ConstantTimeCompare([]byte(k.PublicKey), []byte(MarshalKey(pub))) != 1 {
		return Identity{}, ErrUnknownKey
	}
	if u.Disabled {
		return Identity{}, ErrUserDisabled
	}
	return Identity{
		UserID:      u.ID,
		KeyID:       k.ID,
		Name:        u.Name,
		IsAdmin:     u.IsAdmin,
		Fingerprint: k.Fingerprint,
		KeyType:     k.KeyType,
	}, nil
}

// MarshalKey returns pub as "<type> <base64>", the form stored in the
// database.
func MarshalKey(pub gossh.PublicKey) string {
	return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(pub)))
}

// NewKey checks pub against the key policy and returns the record to
// store. source is store.SourceManual or store.SourceGitHub.
func NewKey(pub gossh.PublicKey, source string) (store.NewKey, error) {
	if err := CheckKeyPolicy(pub); err != nil {
		return store.NewKey{}, err
	}
	return store.NewKey{
		Fingerprint: Fingerprint(pub),
		PublicKey:   MarshalKey(pub),
		KeyType:     pub.Type(),
		Source:      source,
	}, nil
}

// ParsePublicKeys parses public keys in authorized_keys format, one per
// line; blank lines and # comments are skipped. Key options are refused
// and duplicates are dropped. It does not apply the key policy.
func ParsePublicKeys(data []byte) ([]gossh.PublicKey, error) {
	var keys []gossh.PublicKey
	seen := map[string]bool{}
	for i, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		pub, _, options, _, err := gossh.ParseAuthorizedKey(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: not a public key", i+1)
		}
		if len(options) > 0 {
			return nil, fmt.Errorf("line %d: key options are not supported", i+1)
		}
		if fp := Fingerprint(pub); !seen[fp] {
			seen[fp] = true
			keys = append(keys, pub)
		}
	}
	return keys, nil
}
