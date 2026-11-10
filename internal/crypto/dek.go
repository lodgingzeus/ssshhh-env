package crypto

import (
	"crypto/rand"
	"fmt"
)

// DEK is a project's data-encryption key. It exists in plaintext only in
// memory, for the length of one command.
type DEK struct {
	key [KeySize]byte
}

// NewDEK generates a DEK for the project and returns it together with its
// wrapped form, which is the only form that may be stored.
func (k *MasterKey) NewDEK(projectID int64) (*DEK, Sealed, error) {
	aad, err := dekAAD(projectID)
	if err != nil {
		return nil, Sealed{}, err
	}
	var dek DEK
	if _, err := rand.Read(dek.key[:]); err != nil {
		return nil, Sealed{}, fmt.Errorf("crypto: generate DEK: %w", err)
	}
	wrapped, err := seal(&k.key, dek.key[:], aad)
	if err != nil {
		return nil, Sealed{}, err
	}
	return &dek, wrapped, nil
}

// UnwrapDEK recovers the project's DEK. It fails with ErrDecrypt if the
// wrapped key was made with another master key or for another project.
func (k *MasterKey) UnwrapDEK(projectID int64, wrapped Sealed) (*DEK, error) {
	aad, err := dekAAD(projectID)
	if err != nil {
		return nil, err
	}
	raw, err := open(&k.key, wrapped, aad)
	if err != nil {
		return nil, err
	}
	if len(raw) != KeySize {
		return nil, ErrDecrypt
	}
	var dek DEK
	copy(dek.key[:], raw)
	return &dek, nil
}

// SealVersion encrypts one version of an .env file for the row ref names.
func (d *DEK) SealVersion(ref VersionRef, plaintext []byte) (Sealed, error) {
	aad, err := versionAAD(ref)
	if err != nil {
		return Sealed{}, err
	}
	return seal(&d.key, plaintext, aad)
}

// OpenVersion decrypts a version. It fails with ErrDecrypt unless s was
// sealed with this DEK for exactly the row ref names.
func (d *DEK) OpenVersion(ref VersionRef, s Sealed) ([]byte, error) {
	aad, err := versionAAD(ref)
	if err != nil {
		return nil, err
	}
	return open(&d.key, s, aad)
}

// String and GoString keep the key out of logs and error messages if a DEK
// is ever formatted by mistake.
func (d *DEK) String() string   { return "DEK(redacted)" }
func (d *DEK) GoString() string { return d.String() }
