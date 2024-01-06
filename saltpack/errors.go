package saltpack

import (
	"errors"

	"github.com/burlingtonbertie99/mykeys-ext"

	ksaltpack "github.com/keybase/saltpack"
)

// ErrInvalidData if data was invalid.
var ErrInvalidData = errors.New("invalid data")

func convertSignKeyErr(err error) error {
	if kerr, ok := err.(ksaltpack.ErrNoSenderKey); ok {
		if len(kerr.Sender) == 32 {
			spk := keys.NewEdX25519PublicKey(keys.Bytes32(kerr.Sender))
			return keys.NewErrNotFound(spk.ID().String())
		}
	}
	// if err == ksaltpack.ErrNoDecryptionKey {
	// }
	return err
}

func convertBoxKeyErr(err error) error {
	if kerr, ok := err.(ksaltpack.ErrNoSenderKey); ok {
		if len(kerr.Sender) == 32 {
			bpk := keys.NewX25519PublicKey(keys.Bytes32(kerr.Sender))
			return keys.NewErrNotFound(bpk.ID().String())
		}
	}
	// if err == ksaltpack.ErrNoDecryptionKey {
	// }
	return err
}
