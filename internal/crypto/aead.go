// Package crypto implements the envelope encryption that protects secrets
// at rest. A master key wraps one data key (DEK) per project, and the DEK
// encrypts every version of that project's .env files.
//
// The only primitive is XChaCha20-Poly1305 with random nonces. Every
// ciphertext is bound by associated data to the row it belongs to, so a
// blob moved to another row fails to decrypt.
package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// KeySize is the size in bytes of the master key and of every DEK.
const KeySize = chacha20poly1305.KeySize

// ErrDecrypt is returned when a ciphertext cannot be opened: wrong key,
// modified data, or data that belongs to a different row. It deliberately
// does not say which.
var ErrDecrypt = errors.New("crypto: decryption failed")

// Sealed is an encrypted blob and the nonce it was sealed with. Neither is
// secret.
type Sealed struct {
	Nonce      []byte
	Ciphertext []byte
}

// seal encrypts plaintext under key with a fresh random nonce. A 24-byte
// random nonce is safe for any number of messages we will ever seal.
func seal(key *[KeySize]byte, plaintext, aad []byte) (Sealed, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return Sealed{}, fmt.Errorf("crypto: %w", err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return Sealed{}, fmt.Errorf("crypto: read random nonce: %w", err)
	}
	return Sealed{Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, plaintext, aad)}, nil
}

// open decrypts s. Every failure is reported as ErrDecrypt.
func open(key *[KeySize]byte, s Sealed, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, fmt.Errorf("crypto: %w", err)
	}
	if len(s.Nonce) != chacha20poly1305.NonceSizeX {
		return nil, ErrDecrypt
	}
	plaintext, err := aead.Open(nil, s.Nonce, s.Ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}
