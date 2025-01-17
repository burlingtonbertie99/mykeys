// Package saltpack integrates keys with Saltpack (saltpack.org).
package saltpack

import (
	"bytes"
	"crypto/subtle"

	"github.com/burlingtonbertie99/mykeys"
	ksaltpack "github.com/keybase/saltpack"
	"github.com/pkg/errors"
)

// Keyring for Saltpack keys.
type Keyring interface {
	X25519Keys() ([]*keys.X25519Key, error)
}

type saltpack struct {
	kr Keyring
}

func (s *saltpack) X25519Keys() ([]*keys.X25519Key, error) {
	return s.kr.X25519Keys()
}

func newSaltpack(kr Keyring) *saltpack {
	return &saltpack{kr: kr}
}

type store struct {
	keys []*keys.X25519Key
}

func (s *store) X25519Keys() ([]*keys.X25519Key, error) {
	return s.keys, nil
}

// NewKeyring creates keyring for keys.
func NewKeyring(keys ...keys.Key) Keyring {
	return &store{keys: x25519Keys(keys)}
}

func signVersionValidator(version ksaltpack.Version) error {
	switch version.Major {
	case 1, 2:
		return nil
	default:
		return errors.Errorf("unrecognized version %d.%d", version.Major, version.Minor)
	}
}

// func signcryptVersionValidator(version ksaltpack.Version) error {
// 	switch version.Major {
// 	case 1:
// 		return nil
// 	default:
// 		return errors.Errorf("unrecognized version %d.%d", version.Major, version.Minor)
// 	}
// }

func encryptVersionValidator(version ksaltpack.Version) error {
	switch version.Major {
	case 1, 2:
		return nil
	default:
		return errors.Errorf("unrecognized version %d.%d", version.Major, version.Minor)
	}
}

func (s *saltpack) CreateEphemeralKey() (ksaltpack.BoxSecretKey, error) {
	bk := generateBoxKey()
	return bk, nil
}

// LookupBoxSecretKey looks in the Keyring for the secret key corresponding
// to one of the given Key IDs. Returns the index and the key on success,
// or -1 and nil on failure.
func (s *saltpack) LookupBoxSecretKey(kids [][]byte) (int, ksaltpack.BoxSecretKey) {
	if s.kr == nil {
		return -1, nil
	}
	keys, err := s.kr.X25519Keys()
	if err != nil {
		logger.Warningf("Failed to get x25519 keys: %v", err)
		return -1, nil
	}
	for i := 0; i < len(keys); i++ {
		for j := 0; j < len(kids); j++ {
			if subtle.ConstantTimeCompare(keys[i].PublicKey().Bytes()[:], kids[j]) == 1 {
				return j, newBoxKey(keys[i])
			}
		}
	}
	return -1, nil
}

// LookupBoxPublicKey returns a public key given the specified key ID.
// For most cases, the key ID will be the key itself.
func (s *saltpack) LookupBoxPublicKey(kid []byte) ksaltpack.BoxPublicKey {
	if len(kid) != 32 {
		logger.Errorf("LookupBoxPublicKey len(kid) != 32")
		return nil
	}
	return newBoxPublicKey(keys.NewX25519PublicKey(keys.Bytes32(kid)))
}

// GetAllBoxSecretKeys returns all keys, needed if we want to support "hidden"
// receivers via trial and error.
func (s *saltpack) GetAllBoxSecretKeys() []ksaltpack.BoxSecretKey {
	if s.kr == nil {
		return []ksaltpack.BoxSecretKey{}
	}
	keys, err := s.kr.X25519Keys()
	if err != nil {
		logger.Warningf("Failed to get x25519 keys: %v", err)
		return []ksaltpack.BoxSecretKey{}
	}
	boxSecretKeys := make([]ksaltpack.BoxSecretKey, 0, len(keys))
	for _, k := range keys {
		boxSecretKeys = append(boxSecretKeys, newBoxKey(k))
	}
	return boxSecretKeys
}

// ImportBoxEphemeralKey imports the ephemeral key into BoxPublicKey format.
// This key has never been seen before, so will be ephemeral.
func (s *saltpack) ImportBoxEphemeralKey(kid []byte) ksaltpack.BoxPublicKey {
	return boxPublicKeyFromKID(kid)
}

// LookupSigningPublicKey (for ksaltpack.SigKeyring)
func (s *saltpack) LookupSigningPublicKey(b []byte) ksaltpack.SigningPublicKey {
	if len(b) != 32 {
		logger.Errorf("Invalid signing public key bytes")
		return nil
	}
	spk := keys.Bytes32(b)
	return newSignPublicKey(keys.NewEdX25519PublicKey(spk))
}

func containsBoxPublicKey(pk ksaltpack.BoxPublicKey, pks []ksaltpack.BoxPublicKey) bool {
	for _, p := range pks {
		if bytes.Equal(p.ToKID(), pk.ToKID()) {
			return true
		}
	}
	return false
}

func boxPublicKeys(recipients []keys.ID) ([]ksaltpack.BoxPublicKey, error) {
	publicKeys := make([]ksaltpack.BoxPublicKey, 0, len(recipients))
	for _, r := range recipients {
		pk, err := keys.NewX25519PublicKeyFromID(r)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid recipient")
		}
		if pk == nil {
			return nil, errors.Wrapf(err, "recipient not found %s", r)
		}
		bpk := newBoxPublicKey(pk)
		if !containsBoxPublicKey(bpk, publicKeys) {
			publicKeys = append(publicKeys, bpk)
		}
	}
	return publicKeys, nil
}

// func x25519KeyID(senderKey []byte) (keys.ID, error) {
// 	if len(senderKey) != 32 {
// 		return "", errors.Errorf("invalid sender key")
// 	}
// 	bpk := keys.NewX25519PublicKey(keys.Bytes32(senderKey))
// 	return bpk.ID(), nil
// }

func edX25519KeyID(senderKey []byte) (keys.ID, error) {
	if len(senderKey) != 32 {
		return "", errors.Errorf("invalid sender key")
	}
	bpk := keys.NewEdX25519PublicKey(keys.Bytes32(senderKey))
	return bpk.ID(), nil
}

func x25519Keys(ks []keys.Key) []*keys.X25519Key {
	out := make([]*keys.X25519Key, 0, len(ks))
	for _, k := range ks {
		dec := x25519Key(k)
		if dec != nil {
			out = append(out, dec)
		}
	}
	return out
}

func x25519Key(k keys.Key) *keys.X25519Key {
	switch sk := k.(type) {
	case *keys.EdX25519Key:
		return sk.X25519Key()
	case *keys.X25519Key:
		return sk
	default:
		return nil
	}
}
