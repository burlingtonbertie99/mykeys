package noise_test

import (
	"fmt"
	"log"

	"github.com/burlingtonbertie99/mykeys"
	"github.com/burlingtonbertie99/mykeys/noise"
)

func ExampleNewHandshake() {
	alice := keys.GenerateX25519Key()
	bob := keys.GenerateX25519Key()

	na, err := noise.NewHandshake(alice, bob.PublicKey(), true)
	if err != nil {
		log.Fatal(err)
	}

	nb, err := noise.NewHandshake(bob, alice.PublicKey(), false)
	if err != nil {
		log.Fatal(err)
	}

	// -> s
	// <- s
	ha, err := na.Write(nil)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := nb.Read(ha); err != nil {
		log.Fatal(err)
	}
	// -> e, es, ss
	// <- e, ee, se
	hb, err := nb.Write(nil)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := na.Read(hb); err != nil {
		log.Fatal(err)
	}

	// transport I -> R
	ca, err := na.Cipher()
	if err != nil {
		log.Fatal(err)
	}
	encrypted, err := ca.Encrypt(nil, nil, []byte("hello"))
	if err != nil {
		log.Fatal(err)
	}

	cb, err := nb.Cipher()
	if err != nil {
		log.Fatal(err)
	}
	decrypted, err := cb.Decrypt(nil, nil, encrypted)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s", string(decrypted))
	// Output: hello
}
