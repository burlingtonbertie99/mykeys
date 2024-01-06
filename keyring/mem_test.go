package keyring_test

import (
	"testing"

	"github.com/burlingtonbertie99/mykeys/keyring"
)

func TestMemKeyring(t *testing.T) {
	testKeyring(t, keyring.NewMem())
}

func TestMemReset(t *testing.T) {
	testReset(t, keyring.NewMem())
}

func TestMemDocuments(t *testing.T) {
	testDocuments(t, keyring.NewMem())
}
