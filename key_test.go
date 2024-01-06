package keys_test

import (
	"bytes"

	"github.com/burlingtonbertie99/mykeys"
)

func testSeed(b byte) *[32]byte {
	return keys.Bytes32(bytes.Repeat([]byte{b}, 32))
}
