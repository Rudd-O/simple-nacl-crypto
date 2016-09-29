package simplenaclcrypto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/crypto/nacl/secretbox"
	"io"
)

var ErrCorrupted = errors.New("corrupted header or length descriptors")
var ErrBadKey = errors.New("key does not decrypt contents")

func NewLongNonce() ([16]byte, error) {
	var nonce [16]byte
	n, err := rand.Reader.Read(nonce[:])
	if err != nil {
		return nonce, fmt.Errorf("error reading entropy while generating long nonce: %s", err)
	}
	if n != len(nonce) {
		return nonce, fmt.Errorf("short entropy read while generating long nonce")
	}
	return nonce, nil
}

type ShortNonce struct {
	counter uint64
}

func NewShortNonce() *ShortNonce {
	return &ShortNonce{}
}

func (s *ShortNonce) GetAndBump(longNonce [16]byte) ([24]byte, error) {
	var contents [24]byte
	copy(contents[:], longNonce[:])
	binary.BigEndian.PutUint64(contents[16:], s.counter)
	s.counter += 1
	if s.counter == 0 {
		return contents, fmt.Errorf("nonce overflow")
	}
	return contents, nil
}

type EncryptedSerializer struct {
	f           io.Writer
	key         [32]byte
	noncePrefix [16]byte
	sN          *ShortNonce
	wroteHeader bool
}

func NewEncryptedSerializer(f io.Writer, key [32]byte, noncePrefix [16]byte) *EncryptedSerializer {
	return &EncryptedSerializer{f, key, noncePrefix, NewShortNonce(), false}
}

func (e *EncryptedSerializer) Write(b []byte) (int, error) {
	// Create unique message nonce.
	currentN, err := e.sN.GetAndBump(e.noncePrefix)
	if err != nil {
		return 0, fmt.Errorf("cannot bump short nonce: %s", err) // Proper error here.
	}

	// Serialize the size.
	size := ToBinary(len(b) + secretbox.Overhead)
	// Seal into secretbox.
	payload := secretbox.Seal(nil, b, &currentN, &e.key)

	if !e.wroteHeader {
		// Write nonce to the output file now.
		n, err := e.f.Write(e.noncePrefix[:])
		if err != nil {
			return n, fmt.Errorf("cannot write long nonce: %s:", err) // Proper error here.
		}
		e.wroteHeader = true
	}

	// Write size to output file.
	n, err := e.f.Write(size[:])
	if err != nil {
		return n, err
	}

	// Write payload to output file.
	n, err = e.f.Write(payload)
	n -= secretbox.Overhead
	if n < 0 {
		n = 0
	}
	return n, err
}

type EncryptedDeserializer struct {
	f             io.Reader
	key           [32]byte
	noncePrefix   [16]byte
	sN            *ShortNonce
	readHeader    bool
	buf           []byte
	maxAlloc      int
	decryptionBuf []byte
}

func NewEncryptedDeserializer(f io.Reader, key [32]byte, maxAlloc int) *EncryptedDeserializer {
	if maxAlloc == 0 {
		maxAlloc = 1024 * 1024
	}
	return &EncryptedDeserializer{f, key, [16]byte{}, NewShortNonce(), false, []byte{}, maxAlloc, []byte{}}
}

func (e *EncryptedDeserializer) Read(b []byte) (t int, err error) {
	if len(b) == 0 {
		return 0, io.ErrShortBuffer
	}

	if !e.readHeader {
		// Read nonce from the input file now.
		n, err := io.ReadFull(e.f, e.noncePrefix[:])
		if err != nil {
			if err == io.ErrUnexpectedEOF {
				return n, ErrCorrupted
			}
			return n, err
		}
		e.readHeader = true
	}

	for len(b) > 0 {
		for len(e.buf) > 0 && len(b) > 0 {
			n := copy(b, e.buf)
			e.buf = e.buf[n:]
			b = b[n:]
			t += n
		}

		if len(b) > 0 && len(e.buf) == 0 {
			var sparseBuf [8]byte
			// Read and parse length from input file.
			n, err := io.ReadFull(e.f, sparseBuf[:])
			if err != nil {
				if err == io.ErrUnexpectedEOF {
					return t, ErrCorrupted
				}
				return t, err
			}
			packetsize := FromBinary(sparseBuf)
			if packetsize > e.maxAlloc+secretbox.Overhead || packetsize < 1 {
				return t, fmt.Errorf("encrypted packet is too large to be decrypted: %d > %d", packetsize, e.maxAlloc)
			}

			// Allocate buffer.  This will not be allocated on every loop.
			if cap(e.decryptionBuf) < packetsize {
				e.decryptionBuf = make([]byte, packetsize)
			}

			// Read data from input file.
			n, err = io.ReadFull(e.f, e.decryptionBuf[:packetsize])
			if err != nil {
				if err == io.ErrUnexpectedEOF {
					err = ErrCorrupted
				}
				break
			}

			// Create unique message nonce.
			currentN, err := e.sN.GetAndBump(e.noncePrefix)
			if err != nil {
				return t, fmt.Errorf("cannot bump short nonce: %s", err) // Proper error here.
			}

			// Open from secretbox.
			payload, ok := secretbox.Open(nil, e.decryptionBuf[:n], &currentN, &e.key)
			if !ok {
				return t, ErrBadKey
			}
			e.buf = append(e.buf, payload...)
		}
	}
	return t, err
}
