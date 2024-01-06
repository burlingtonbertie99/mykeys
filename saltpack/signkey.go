package saltpack

import (
	"golang.org/x/crypto/ed25519"

	"github.com/burlingtonbertie99/mykeys"
	ksaltpack "github.com/keybase/saltpack"
	"golang.org/x/crypto/nacl/sign"
)

// signKey is a wrapper for keys.SignKey.
type signKey struct {
	ksaltpack.SigningSecretKey
	privateKey *[ed25519.PrivateKeySize]byte
	publicKey  *keys.EdX25519PublicKey
}

// newSignKey creates SigningSecretKey from a keys.SignKey.
func newSignKey(sk *keys.EdX25519Key) *signKey {
	return &signKey{
		privateKey: sk.PrivateKey(),
		publicKey:  sk.PublicKey(),
	}
}

func (k *signKey) Sign(message []byte) ([]byte, error) {
	signedMessage := sign.Sign(nil, message, k.privateKey)
	return signedMessage[:sign.Overhead], nil
}

func (k *signKey) GetPublicKey() ksaltpack.SigningPublicKey {
	return newSignPublicKey(k.publicKey)
}

// signPublicKey is a wrapper for keys.SignPublicKey.
type signPublicKey struct {
	ksaltpack.SigningPublicKey
	pk *keys.EdX25519PublicKey
}

// newSignPublicKey creates SignPublicKey for keys.SignPublicKey.
func newSignPublicKey(pk *keys.EdX25519PublicKey) *signPublicKey {
	return &signPublicKey{pk: pk}
}

func (k signPublicKey) ToKID() []byte {
	return k.pk.Bytes()[:]
}

func (k signPublicKey) Verify(message []byte, signature []byte) error {
	signedMessage := append(signature, message...)
	_, err := k.pk.Verify(signedMessage)
	return err
}
