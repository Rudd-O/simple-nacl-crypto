package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/Rudd-O/simple-nacl-crypto"
	"io"
	"log"
	"os"
	"syscall"
)

var sparse bool
var bufsize = 0

func init() {
	flag.BoolVar(&sparse, "s", false, "encrypt the file using an encoding that compresses blocks of zeroes")
	flag.IntVar(&bufsize, "b", 0, "use maximum buffer of this many bytes (default: unbuffered)")
}

func usage(s string) {
	if len(s) > 0 {
		s = fmt.Sprintf("error: %s\n", s)
	}
	postfix := "-s denotes whether to store the file in a sparse format"
	log.Fatalf("%susage: nacl-crypt <enc | dec> [-s] <infile> <outfile> <key>\n%s\n", s, postfix)
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) < 4 {
		usage("not enough arguments")
	}

	mode := args[0]
	if mode != "enc" && mode != "dec" {
		usage("encryption mode must be 'enc' or 'dec'")
	}
	fn := args[1]
	outfn := args[2]
	key := []byte(args[3])

	// DO NOT do this.  Use the output of scrypt.
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
	fReader := io.Reader(f)
	oWriter := io.Writer(o)

	bufferReader := func(i io.Reader) io.Reader {
		if bufsize > 0 {
			return bufio.NewReaderSize(i, bufsize)
		}
		return i
	}
	bufferWriter := func(o io.Writer) (io.Writer, *bufio.Writer) {
		if bufsize > 0 {
			b := bufio.NewWriterSize(o, bufsize)
			return b, b
		}
		return o, nil
	}

	// Trim the output file to prevent incorrect contents.
	err = syscall.Ftruncate(int(o.Fd()), 0)
	if err != nil {
		log.Fatalf("cannot truncate %s: %s", o.Name(), err)
	}

	if mode == "enc" {
		// Create nonces.
		lN, err := simplenaclcrypto.NewLongNonce()
		if err != nil {
			log.Fatalf("cannot create nonce: %s:", f.Name(), err)
		}
		oWriter = simplenaclcrypto.NewEncryptedSerializer(oWriter, keyPadded, lN)
		// Store sparse mode.
		if sparse {
			sparseBuf := simplenaclcrypto.ToBinary(1)
			oWriter.Write(sparseBuf[:])
			if err != nil {
				log.Fatalf("cannot write sparse flag to %s: %s", o.Name(), err)
			}
			fReader = simplenaclcrypto.NewSparseEncoder(fReader)
		} else {
			sparseBuf := simplenaclcrypto.ToBinary(0)
			oWriter.Write(sparseBuf[:])
		}
	} else {
		fReader = simplenaclcrypto.NewEncryptedDeserializer(fReader, keyPadded, bufsize)

		// Detect whether sparse mode was requested.
		var sparseBuf [8]byte
		_, err = fReader.Read(sparseBuf[:])
		if err != nil {
			log.Fatalf("cannot read sparse flag from %s: %s", f.Name(), err)
		}
		if sparse := simplenaclcrypto.FromBinary(sparseBuf); sparse == 1 {
			oWriter = simplenaclcrypto.NewSparseDecoder(o)
		} else if sparse != 0 {
			log.Fatalf("invalid sparse flag: %d", sparse)
		}
	}

	fReader = bufferReader(fReader)
	oWriter, flusher := bufferWriter(oWriter)

	// Perform encryption / decryption.
	_, err = io.Copy(oWriter, fReader)
	if err != nil {
		log.Fatalf("cannot copy from %s to %s: %s", f.Name(), o.Name(), err)
	}
	if flusher != nil {
		err = flusher.Flush()
		if err != nil {
			log.Fatalf("cannot copy from %s to %s: %s", f.Name(), o.Name(), err)
		}
	}
}
