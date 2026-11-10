package crypto

import (
	"encoding/binary"
	"errors"
)

// Associated-data prefixes. Each kind of ciphertext has its own, so a
// wrapped DEK can never be opened as a version or the other way round. The
// "v1" lets the layout change later without ambiguity.
const (
	dekAADPrefix     = "ssshhh-env:dek:v1\x00"
	versionAADPrefix = "ssshhh-env:version:v1\x00"
)

var errBadRef = errors.New("crypto: row ids must be positive")

// VersionRef identifies the row a version's ciphertext belongs to.
type VersionRef struct {
	ProjectID int64
	EnvID     int64
	Version   int64
}

// dekAAD binds a wrapped DEK to its project. Ids are fixed-width, so two
// different rows can never produce the same bytes.
func dekAAD(projectID int64) ([]byte, error) {
	if projectID <= 0 {
		return nil, errBadRef
	}
	return appendIDs([]byte(dekAADPrefix), projectID), nil
}

// versionAAD binds a version's ciphertext to its project, environment and
// version number.
func versionAAD(ref VersionRef) ([]byte, error) {
	if ref.ProjectID <= 0 || ref.EnvID <= 0 || ref.Version <= 0 {
		return nil, errBadRef
	}
	return appendIDs([]byte(versionAADPrefix), ref.ProjectID, ref.EnvID, ref.Version), nil
}

func appendIDs(b []byte, ids ...int64) []byte {
	for _, id := range ids {
		b = binary.BigEndian.AppendUint64(b, uint64(id)) // #nosec G115 -- callers reject ids <= 0
	}
	return b
}
