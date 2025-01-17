package keys_test

import (
	"bytes"
	"testing"

	"github.com/burlingtonbertie99/mykeys"
	"github.com/burlingtonbertie99/mykeys/encoding"
	"github.com/stretchr/testify/require"
)

func TestSecretBox(t *testing.T) {
	sk := keys.Rand32()
	b := []byte{0x01, 0x02, 0x03}
	encrypted := keys.SecretBoxSeal(b, sk)
	out, err := keys.SecretBoxOpen(encrypted, sk)
	require.NoError(t, err)
	require.Equal(t, b, out)
}

func TestSecretBoxSeal(t *testing.T) {
	key := keys.Bytes32(encoding.MustDecode("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389", encoding.Hex))
	iv := keys.Bytes24(encoding.MustDecode("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37", encoding.Hex))
	plain := encoding.MustDecode("be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc"+
		"e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31"+
		"0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde"+
		"048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864"+
		"5e0705", encoding.Hex)
	cipher := encoding.MustDecode("f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce"+
		"48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c972"+
		"71d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae"+
		"90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b3"+
		"7973f622a43d14a6599b1f654cb45a74e355a5", encoding.Hex)

	encrypted := keys.PrivSecretBoxSeal(plain, iv, key)
	require.Equal(t, iv[:], encrypted[:24])
	require.Equal(t, cipher, encrypted[24:])

	out, err := keys.PrivSecretBoxOpen(encrypted, key)
	require.NoError(t, err)
	require.Equal(t, plain, out)
}

func TestEncryptWithPassword(t *testing.T) {
	b := bytes.Repeat([]byte{0x01}, 64)
	encrypted := keys.EncryptWithPassword(b, "password123")

	out, err := keys.DecryptWithPassword(encrypted, "password123")
	require.NoError(t, err)
	require.Equal(t, b, out)

	out, err = keys.DecryptWithPassword(encrypted, "invalid")
	require.Nil(t, out)
	require.EqualError(t, err, "failed to decrypt with a password: secretbox open failed")

	out, err = keys.DecryptWithPassword([]byte{}, "password123")
	require.Nil(t, out)
	require.EqualError(t, err, "failed to decrypt with a password: not enough bytes")

	out, err = keys.DecryptWithPassword(bytes.Repeat([]byte{0x01}, 16), "password123")
	require.Nil(t, out)
	require.EqualError(t, err, "failed to decrypt with a password: not enough bytes")

	out, err = keys.DecryptWithPassword(bytes.Repeat([]byte{0x01}, 24), "password123")
	require.Nil(t, out)
	require.EqualError(t, err, "failed to decrypt with a password: not enough bytes")

	out, err = keys.DecryptWithPassword(bytes.Repeat([]byte{0x01}, 32), "password123")
	require.Nil(t, out)
	require.EqualError(t, err, "failed to decrypt with a password: not enough bytes")

	out, err = keys.DecryptWithPassword(bytes.Repeat([]byte{0x01}, 40), "password123")
	require.Nil(t, out)
	require.EqualError(t, err, "failed to decrypt with a password: secretbox open failed")
}
