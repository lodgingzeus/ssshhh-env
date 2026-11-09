// Package auth decides which client public keys are acceptable and who they
// belong to.
package auth

import (
	"crypto/rsa"
	"errors"
	"fmt"

	gossh "golang.org/x/crypto/ssh"
)

// MinRSABits is the smallest RSA modulus accepted for client keys.
const MinRSABits = 3072

// ErrWeakKey is returned for key types or sizes the server refuses.
var ErrWeakKey = errors.New("key type or size not allowed")

// CheckKeyPolicy reports whether pub is a key type the server accepts:
// ed25519, ECDSA, FIDO (sk-*) keys, or RSA of at least MinRSABits.
// DSA, small RSA and certificates are refused.
func CheckKeyPolicy(pub gossh.PublicKey) error {
	switch pub.Type() {
	case gossh.KeyAlgoED25519,
		gossh.KeyAlgoECDSA256, gossh.KeyAlgoECDSA384, gossh.KeyAlgoECDSA521,
		gossh.KeyAlgoSKED25519, gossh.KeyAlgoSKECDSA256:
		return nil
	case gossh.KeyAlgoRSA:
		cpk, ok := pub.(gossh.CryptoPublicKey)
		if !ok {
			return ErrWeakKey
		}
		rk, ok := cpk.CryptoPublicKey().(*rsa.PublicKey)
		if !ok {
			return ErrWeakKey
		}
		if bits := rk.N.BitLen(); bits < MinRSABits {
			return fmt.Errorf("%w: RSA %d bits, need at least %d", ErrWeakKey, bits, MinRSABits)
		}
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrWeakKey, pub.Type())
	}
}

// Fingerprint returns the OpenSSH-style SHA256 fingerprint of pub.
func Fingerprint(pub gossh.PublicKey) string {
	return gossh.FingerprintSHA256(pub)
}
