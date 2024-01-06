package keys

import "io"

// Key with id, type and private and/or public data.
type Key interface {
	// ID for the key.
	ID() ID

	// Type of key.
	Type() KeyType

	// Private key data.
	Private() []byte

	// Public key data.
	Public() []byte
}

// KeyType ...
type KeyType string

func (t KeyType) GenerateKey(reader io.Reader, i int) interface{} {

	return nil
	//
}

var _ Key = &EdX25519Key{}
var _ Key = &EdX25519PublicKey{}

var _ Key = &X25519Key{}
var _ Key = &X25519PublicKey{}

var _ Key = &SGXHSMKey{}
var _ Key = &SGXHSMPublicKey{}

var _ Key = ID("")
