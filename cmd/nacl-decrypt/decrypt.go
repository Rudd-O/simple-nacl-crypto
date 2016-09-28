package main

import (
	"github.com/Rudd-O/simple-nacl-crypto"
	"io"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 4 {
		log.Fatalf("usage: decrypt <infile> <outfile> <key>")
	}

	fn := os.Args[1]
	outfn := os.Args[2]

	// DO NOT do this.  Use the output of scrypt.
	key := []byte(os.Args[3])
	var keyPadded [32]byte
	copy(keyPadded[:], key[:])

	// Open input and output files.
	f, err := os.Open(fn)
	if err != nil {
		log.Fatalf("cannot open %s: %s:", fn, err)
	}
	o, err := os.OpenFile(outfn, os.O_WRONLY|os.O_CREATE, 0666) // Mode is wrong.
	if err != nil {
		log.Fatalf("cannot open %s: %s:", outfn, err)
	}

	iff := simplenaclcrypto.NewEncryptedDeserializer(f, keyPadded)
	_, err = io.Copy(o, iff)
	if err != nil {
		log.Fatalf("cannot copy from %s to %s: %s", fn, outfn, err)
	}
}
