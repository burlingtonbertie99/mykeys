package keyring_test

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/burlingtonbertie99/mykeys/keyring"
	"github.com/stretchr/testify/require"
)

func testFS(t *testing.T) (keyring.Keyring, func()) {
	dir, err := ioutil.TempDir("", "KeysTest.")
	require.NoError(t, err)
	fs, err := keyring.NewFS(dir)
	require.NoError(t, err)
	closeFn := func() {
		os.RemoveAll(dir)
	}
	return fs, closeFn
}

func TestFS(t *testing.T) {
	st, closeFn := testFS(t)
	defer closeFn()
	testKeyring(t, st)

	_, err := st.Get(".")
	require.EqualError(t, err, "invalid id .")
	_, err = st.Get("..")
	require.EqualError(t, err, "invalid id ..")
}

func TestFSReset(t *testing.T) {
	st, closeFn := testFS(t)
	defer closeFn()
	testReset(t, st)
}

func TestFSDocuments(t *testing.T) {
	st, closeFn := testFS(t)
	defer closeFn()
	testDocuments(t, st)
}
