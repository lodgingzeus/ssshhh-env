package auth

import (
	"bytes"
	"fmt"
	"os"
	"regexp"

	gossh "golang.org/x/crypto/ssh"
)

// Identity is a known key and the name it belongs to.
type Identity struct {
	Name        string
	Fingerprint string
	KeyType     string
}

// Allowlist maps key fingerprints to identities. It is read once at startup
// and is immutable afterwards, so it is safe for concurrent use.
//
// It is a stand-in until users and keys move into the database.
type Allowlist struct {
	byFingerprint map[string]Identity
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

// LoadAllowlist reads an authorized_keys-style file. Every line must be
// "<type> <base64> <name>". Key options are not supported, every key must
// pass CheckKeyPolicy, and the file must not be group- or world-writable.
// Any problem is an error, so a bad entry fails at startup.
func LoadAllowlist(path string) (*Allowlist, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("allowlist: %w", err)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("allowlist %s: mode %04o is group/world-writable", path, fi.Mode().Perm())
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path from a CLI flag
	if err != nil {
		return nil, fmt.Errorf("allowlist: %w", err)
	}
	return parseAllowlist(data)
}

func parseAllowlist(data []byte) (*Allowlist, error) {
	a := &Allowlist{byFingerprint: map[string]Identity{}}
	for i, line := range bytes.Split(data, []byte("\n")) {
		lineNo := i + 1
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		pub, comment, options, _, err := gossh.ParseAuthorizedKey(line)
		if err != nil {
			return nil, fmt.Errorf("allowlist line %d: %w", lineNo, err)
		}
		if len(options) > 0 {
			return nil, fmt.Errorf("allowlist line %d: key options are not supported", lineNo)
		}
		if !nameRe.MatchString(comment) {
			return nil, fmt.Errorf("allowlist line %d: name %q must match %s", lineNo, comment, nameRe)
		}
		if err := CheckKeyPolicy(pub); err != nil {
			return nil, fmt.Errorf("allowlist line %d: %w", lineNo, err)
		}
		fp := Fingerprint(pub)
		if _, dup := a.byFingerprint[fp]; dup {
			return nil, fmt.Errorf("allowlist line %d: duplicate key %s", lineNo, fp)
		}
		a.byFingerprint[fp] = Identity{Name: comment, Fingerprint: fp, KeyType: pub.Type()}
	}
	return a, nil
}

// Lookup returns the identity for pub, if it is allowed.
func (a *Allowlist) Lookup(pub gossh.PublicKey) (Identity, bool) {
	if a == nil || pub == nil {
		return Identity{}, false
	}
	id, ok := a.byFingerprint[Fingerprint(pub)]
	return id, ok
}

// Len returns the number of allowed keys.
func (a *Allowlist) Len() int { return len(a.byFingerprint) }
