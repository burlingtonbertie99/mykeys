package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
)

// SGXHSM2 key type.
const SGXHSM2 KeyType = "SGXHSM2"
const SGXHSM2KeyHRP = "SGXHSM2"

// SGXHSM2PublicKey is the public part of SGXHSM2 key pair.
type SGXHSM2PublicKey struct {
	id ID
	//pk *SGXHSM2.PublicKey
}

// SGXHSM2Key implements Key interface for SGXHSM2.
type SGXHSM2Key struct {
	//	privateKey *SGXHSM2.PrivateKey
	publicKey *SGXHSM2PublicKey
}

/*
// NewSGXHSM2KeyFromBytes constructs SGXHSM2 from a private key (PKCS1).
func NewSGXHSM2KeyFromBytes(privateKey []byte) (*SGXHSM2Key, error) {
	k, err := x509.ParsePKCS1PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return NewSGXHSM2Key(k), nil
}

*/

/*
func keyIDFromSGXHSM2(k *SGXHSM2) ID {
	// SHA256 of PKCS1 public key
	b := x509.MarshalPKCS1PublicKey(k)
	hasher := crypto.SHA256.New()
	_, err := hasher.Write(b)
	if err != nil {
		panic(err)
	}
	return MustID(SGXHSM2KeyHRP, hasher.Sum(nil))
}

*/

/*
// NewSGXHSM2Key from SGXHSM2.PrivateKey.
func NewSGXHSM2Key(k *SGXHSM2) *SGXHSM2Key {
	pk := NewSGXHSM2PublicKey(&k)
	return &SGXHSM2Key{k, pk}
}

*/

// PublicKey ...
func (k *SGXHSM2Key) PublicKey() *SGXHSM2PublicKey {
	return k.publicKey
}

// ID for the key.
func (k *SGXHSM2Key) ID() ID {
	return k.publicKey.ID()
}

// Type of key.
func (k *SGXHSM2Key) Type() KeyType {
	return SGXHSM2
}

// Private key data (PKCS1).
//func (k *SGXHSM2Key) Private() []byte {
//	return x509.MarshalPKCS1PrivateKey(k.privateKey)
//}

// Public key data (PKCS1).
func (k *SGXHSM2Key) Public() []byte {
	return k.publicKey.Public()
}

/*
// NewSGXHSM2PublicKey returns SGXHSM2 public key.
func NewSGXHSM2PublicKey(pk *SGXHSM2) *SGXHSM2PublicKey {
	id := keyIDFromSGXHSM2(pk)
	return &SGXHSM2PublicKey{id, pk}
}

*/

// SGXHSMPublicKey is the public part of SGXHSM key pair.
type PublicKey struct {
	id        ID
	publicKey *[1024]byte
}

// SGXHSMKey SGXHSMPublicKey is a SGXHSM key capable of signing and encryption
type SGXHSMKey2 struct {
	privateKey *[ed25519.PrivateKeySize]byte
	publicKey  *EdX25519PublicKey
}

// NewSGXHSM2PublicKeyFromBytes returns SGXHSM2 public key from PKC1 bytes.
func NewSGXHSM2PublicKeyFromBytes(publicKey []byte) (*SGXHSM2PublicKey, error) {
	pk, err := x509.ParsePKCS1PublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return NewSGXHSM2PublicKey(pk), nil
}

func NewSGXHSM2PublicKey(pk *rsa.PublicKey) *SGXHSM2PublicKey {

	return nil

}

// ID is key identifier.
func (k *SGXHSM2PublicKey) ID() ID {
	return k.id
}

// Bytes for public key (PKCS1).
func (k *SGXHSM2PublicKey) Bytes() []byte {
	//return x509.MarshalPKCS1PublicKey(k.pk)

	return nil
}

// Public key data.
func (k *SGXHSM2PublicKey) Public() []byte {
	return k.Bytes()
}

// Private returns nil.
func (k *SGXHSM2PublicKey) Private() []byte {
	return nil
}

// Type of key.
func (k *SGXHSM2PublicKey) Type() KeyType {
	return SGXHSM2
}

// GenerateSGXHSM2Key generates a SGXHSM2 key.
func GenerateSGXHSM2Key() string {
	err := SGXHSM2.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}
	//return NewSGXHSM2Key(priv)

	return "NYI"

}
