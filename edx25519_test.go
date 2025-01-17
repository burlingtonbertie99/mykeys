package keys_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"testing"

	"github.com/burlingtonbertie99/mykeys"
	"github.com/burlingtonbertie99/mykeys/encoding"
	"github.com/stretchr/testify/require"
)

func TestEdX25519KeySeed(t *testing.T) {
	sk := keys.GenerateEdX25519Key()
	seed := sk.Seed()
	skOut := keys.NewEdX25519KeyFromSeed(seed)
	require.Equal(t, sk.PrivateKey(), skOut.PrivateKey())
	require.True(t, sk.Equal(skOut))

	sk2 := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	require.False(t, sk.Equal(sk2))
}

func TestEdX25519KeyPaperKey(t *testing.T) {
	k := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	paperKey := k.PaperKey()
	require.Equal(t, "absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice comic", paperKey)
}

func TestEdX25519KeySignVerify(t *testing.T) {
	signKey := keys.GenerateEdX25519Key()

	b := []byte("test message")
	sig := signKey.Sign(b)

	bout, err := signKey.PublicKey().Verify(sig)
	require.NoError(t, err)
	require.Equal(t, b, bout)

	_, err = signKey.PublicKey().Verify(sig[0 : len(sig)-1])
	require.EqualError(t, err, "verify failed")

	sig2 := signKey.SignDetached(b)
	err = signKey.PublicKey().VerifyDetached(sig2, b)
	require.NoError(t, err)

	err = signKey.PublicKey().VerifyDetached(sig2, []byte{0x01})
	require.EqualError(t, err, "verify failed")
}

func TestNewEdX25519KeyFromPrivateKey(t *testing.T) {
	_ = keys.NewEdX25519KeyFromPrivateKey(keys.Bytes64(bytes.Repeat([]byte{0x01}, 64)))
}

func TestX25519Match(t *testing.T) {
	sk := keys.GenerateEdX25519Key()
	bid := sk.X25519Key().ID()

	sk2 := keys.GenerateEdX25519Key()
	bid2 := sk2.X25519Key().ID()

	require.True(t, keys.X25519Match(sk.ID(), sk.ID()))
	require.True(t, keys.X25519Match(sk.ID(), bid))
	require.True(t, keys.X25519Match(bid, bid))
	require.True(t, keys.X25519Match(bid, sk.ID()))

	require.False(t, keys.X25519Match(sk.ID(), sk2.ID()))
	require.False(t, keys.X25519Match(sk.ID(), bid2))
	require.False(t, keys.X25519Match(bid, bid2))
	require.False(t, keys.X25519Match(bid, sk2.ID()))
}

func ExampleGenerateEdX25519Key() {
	alice := keys.GenerateEdX25519Key()
	fmt.Printf("Alice: %s\n", alice.ID())
}

func ExampleEdX25519Key_Sign() {
	alice := keys.GenerateEdX25519Key()
	msg := "I'm alice 🤓"
	sig := alice.Sign([]byte(msg))
	out, err := alice.PublicKey().Verify(sig)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", string(out))
	// Output:
	// I'm alice 🤓
}

func TestSign(t *testing.T) {
	// private := encoding.MustDecode("b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd", encoding.Hex)
	// public := encoding.MustDecode("77f48b59caeda77751ed138b0ec667ff50f8768c25d48309a8f386a2bad187fb", encoding.Hex)
	kp := encoding.MustDecode("b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd"+
		"77f48b59caeda77751ed138b0ec667ff50f8768c25d48309a8f386a2bad187fb", encoding.Hex)
	msg := encoding.MustDecode("916c7d1d268fc0e77c1bef238432573c39be577bbea0998936add2b50a653171"+
		"ce18a542b0b7f96c1691a3be6031522894a8634183eda38798a0c5d5d79fbd01"+
		"dd04a8646d71873b77b221998a81922d8105f892316369d5224c9983372d2313"+
		"c6b1f4556ea26ba49d46e8b561e0fc76633ac9766e68e21fba7edca93c4c7460"+
		"376d7f3ac22ff372c18f613f2ae2e856af40", encoding.Hex)
	sig := encoding.MustDecode("6bd710a368c1249923fc7a1610747403040f0cc30815a00f9ff548a896bbda0b"+
		"4eb2ca19ebcf917f0f34200a9edbad3901b64ab09cc5ef7b9bcc3c40c0ff7509", encoding.Hex)

	key := keys.NewEdX25519KeyFromPrivateKey(keys.Bytes64(kp))

	out := key.Sign(msg)
	require.Equal(t, sig, out[:64])

	out = key.SignDetached(msg)
	require.Equal(t, sig, out)
}

func TestEdX25519JSON(t *testing.T) {
	seed := keys.Bytes32(bytes.Repeat([]byte{0x01}, 32))

	key := keys.NewEdX25519KeyFromSeed(seed)

	type test struct {
		Key *keys.EdX25519Key `json:"key"`
	}

	b, err := json.Marshal(test{Key: key})
	require.NoError(t, err)
	expected := `{"key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}`

	require.Equal(t, expected, string(b))
	var out test
	err = json.Unmarshal(b, &out)
	require.NoError(t, err)
	require.Equal(t, key.Private(), out.Key.Private())
	require.Equal(t, key.Public(), out.Key.Public())

	// 64 byte private key
	old := `{"key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQGKiOPddAnxlf1S2y08ul1yymcJvx2UEhvzdIgBtA9vXA=="}`
	err = json.Unmarshal([]byte(old), &out)
	require.NoError(t, err)
	require.Equal(t, key.Private(), out.Key.Private())
	require.Equal(t, key.Public(), out.Key.Public())
}
