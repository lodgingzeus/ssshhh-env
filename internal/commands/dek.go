package commands

import (
	"fmt"

	"github.com/lodgingzeus/ssshhh-env/internal/crypto"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// newProjectDEK returns the store callback that generates and wraps the
// data key for a project being created.
func newProjectDEK(mk *crypto.MasterKey) func(projectID int64) (store.WrappedDEK, error) {
	return func(projectID int64) (store.WrappedDEK, error) {
		_, wrapped, err := mk.NewDEK(projectID)
		if err != nil {
			return store.WrappedDEK{}, err
		}
		return store.WrappedDEK{Nonce: wrapped.Nonce, Ciphertext: wrapped.Ciphertext, MasterKeyID: mk.ID()}, nil
	}
}

// projectDEK unwraps the project's data key. A key wrapped under another
// master key is reported as that, not as a bare decryption failure.
func projectDEK(mk *crypto.MasterKey, p store.Project) (*crypto.DEK, error) {
	if p.MasterKeyID != mk.ID() {
		return nil, fmt.Errorf("project data key is wrapped with master key %s, but the server holds %s", p.MasterKeyID, mk.ID())
	}
	return mk.UnwrapDEK(p.ID, crypto.Sealed{Nonce: p.DEKNonce, Ciphertext: p.WrappedDEK})
}
