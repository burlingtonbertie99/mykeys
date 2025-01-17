package api_test

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/burlingtonbertie99/mykeys"
	"github.com/burlingtonbertie99/mykeys/api"
	"github.com/stretchr/testify/require"
)

func TestNewKey(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	key := api.NewKey(sk)

	require.Equal(t, sk.ID(), key.ID)
	require.Equal(t, sk.Private(), key.Private)
	require.Equal(t, sk.Public(), key.Public)
	require.Equal(t, "edx25519", key.Type)

	require.Equal(t, sk, key.AsEdX25519())
	require.Equal(t, sk.X25519Key(), key.AsX25519())
	require.Equal(t, sk.X25519Key().PublicKey(), key.AsX25519Public())
}

func TestIDKey(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	kid := sk.ID()
	key := api.NewKey(kid)

	require.Equal(t, kid, key.ID)

	require.Equal(t, sk.PublicKey(), key.AsEdX25519Public())
	require.Equal(t, sk.X25519Key().PublicKey(), key.AsX25519Public())
}

func TestNewKeyPublic(t *testing.T) {
	spk := keys.NewEdX25519KeyFromSeed(testSeed(0x01)).PublicKey()
	key := api.NewKey(spk)

	require.Equal(t, spk.ID(), key.ID)
	require.Equal(t, spk.Bytes(), key.Public)
	require.Nil(t, spk.Private())
	require.Equal(t, "edx25519", key.Type)
	require.True(t, spk.ID().IsEdX25519())
	require.True(t, key.IsEdX25519())

	require.Equal(t, spk, key.AsEdX25519Public())
}

func TestNewKeyX25519(t *testing.T) {
	sk := keys.NewX25519KeyFromSeed(testSeed(0x01))
	key := api.NewKey(sk)

	require.Equal(t, sk.ID(), key.ID)
	require.Equal(t, sk.Private(), key.Private)
	require.Equal(t, sk.Public(), key.Public)
	require.Equal(t, "x25519", key.Type)
	require.True(t, sk.ID().IsX25519())
	require.True(t, key.IsX25519())

	require.Equal(t, sk, key.AsX25519())
	require.Nil(t, key.AsEdX25519())
}

func TestNewKeyX25519Public(t *testing.T) {
	spk := keys.NewX25519KeyFromSeed(testSeed(0x01)).PublicKey()
	key := api.NewKey(spk)

	require.Equal(t, spk.ID(), key.ID)
	require.Equal(t, spk.Bytes(), key.Public)
	require.Nil(t, spk.Private())
	require.Equal(t, "x25519", key.Type)

	require.Equal(t, spk, key.AsX25519Public())
}

func TestKeyLabel(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	key := api.NewKey(sk)

	key.WithLabels("test")
	require.Equal(t, key.Labels, api.Labels{"test"})

	key.WithLabels("channel", "channel")
	require.Equal(t, key.Labels, api.Labels{"test", "channel"})
}

func TestKeyLabelDB(t *testing.T) {
	labels := api.Labels([]string{"label1", "label2"})

	val, err := labels.Value()
	require.NoError(t, err)
	require.Equal(t, "^label1$,^label2$", val.(string))
	str := val.(string)

	var out api.Labels
	err = out.Scan(str)
	require.NoError(t, err)
	require.Equal(t, labels, out)
}

func TestKeyExtDB(t *testing.T) {
	m := map[string]interface{}{"test": float64(1)}
	ext := api.Ext(m)

	val, err := ext.Value()
	require.NoError(t, err)
	require.Equal(t, `{"test":1}`, val.(string))
	str := val.(string)

	var out api.Ext
	err = out.Scan(str)
	require.NoError(t, err)
	require.Equal(t, ext, out)
}

func TestKeyExtDBNil(t *testing.T) {
	ext := api.Ext(nil)
	val, err := ext.Value()
	require.NoError(t, err)
	require.Equal(t, ``, val.(string))
	str := val.(string)

	var out api.Ext
	err = out.Scan(str)
	require.NoError(t, err)
	require.Equal(t, ext, out)
}

func TestKeyEqual(t *testing.T) {
	k1 := api.NewKey(keys.NewEdX25519KeyFromSeed(testSeed(0x01)))
	k1.SetExtString("token", "token1")
	k2 := api.NewKey(keys.NewEdX25519KeyFromSeed(testSeed(0x01)))
	k2.SetExtString("token", "token1")
	require.True(t, k1.Equal(k2))

	k2.SetExtString("token", "token2")
	require.False(t, k1.Equal(k2))
}

func testSeed(b byte) *[32]byte {
	return keys.Bytes32(bytes.Repeat([]byte{b}, 32))
}

func testdata(t *testing.T, path string) []byte {
	b, err := ioutil.ReadFile(path)
	require.NoError(t, err)
	b = bytes.ReplaceAll(b, []byte{'\r'}, []byte{})
	return b
}
