package simplenaclcrypto

import (
	"bytes"
	"encoding/binary"
	"io"
	"reflect"
	"syscall"
)

var FALLOC_FL_PUNCH_HOLE uint32 = 2
var FALLOC_FL_KEEP_SIZE uint32 = 1
var FALLOC_ERASE = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE

func getFd(f io.Writer) int {
	st := reflect.ValueOf(f)
	if st.IsValid() {
		meth := st.MethodByName("Fd")
		if meth.IsValid() {
			rets := meth.Call([]reflect.Value{})
			if len(rets) == 1 {
				if rets[0].Kind() == reflect.Uintptr {
					return int(rets[0].Uint())
				}
			}
		}
	}
	return 0
}

func ToBinary(number int) [8]byte {
	num := uint64(number)
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], num)
	return data
}

func FromBinary(data [8]byte) int {
	num := binary.BigEndian.Uint64(data[:])
	return int(num)
}

func setBit(n uint64, pos uint) uint64 {
	n |= (1 << pos)
	return n
}

// Clears the bit at pos in n.
func clearBit(n uint64, pos uint) uint64 {
	mask := uint64(^(1 << pos))
	n &= mask
	return n
}

func isBitSet(n uint64, pos uint) bool {
	mask := uint64((1 << pos))
	return n&mask != 0
}

func flagNonSparse(n uint64) uint64 {
	return clearBit(n, 63)
}

func flagSparse(n uint64) uint64 {
	return setBit(n, 63)
}

func flagIsSparse(n uint64) (bool, uint64) {
	return isBitSet(n, 63), clearBit(n, 63)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type SparseEncoder struct {
	f                    io.Reader
	unsentSparseBlocks   uint32
	unsentNonSparseData  []byte
	unsentSerializedData []byte
	unprocessedData      []byte
}

func NewSparseEncoder(f io.Reader) *SparseEncoder {
	return &SparseEncoder{
		f: f,
	}
}

func (e *SparseEncoder) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, io.ErrShortBuffer
	}

	var empty [512]byte
	var n int
	var t int
	var err error
	originalblen := len(b)

	flushNonSparse := func() bool {
		if e.unsentSparseBlocks == 0 && len(e.unsentNonSparseData) > 0 {
			var chunk [8]byte
			binary.BigEndian.PutUint64(chunk[:], flagNonSparse(uint64(len(e.unsentNonSparseData))))
			e.unsentSerializedData = append(e.unsentSerializedData, chunk[:]...)
			e.unsentSerializedData = append(e.unsentSerializedData, e.unsentNonSparseData...)
			e.unsentNonSparseData = []byte{}
			return true
		}
		return false
	}
	flushSparse := func() bool {
		if e.unsentSparseBlocks != 0 {
			var chunk [8]byte
			binary.BigEndian.PutUint64(chunk[:], flagSparse(uint64(e.unsentSparseBlocks)))
			e.unsentSerializedData = append(e.unsentSerializedData, chunk[:]...)
			e.unsentSparseBlocks = 0
			return true
		}
		return false
	}
	flushUnsent := func() {
		for len(e.unsentSerializedData) > 0 && len(b) > 0 {
			n = copy(b, e.unsentSerializedData)
			e.unsentSerializedData = e.unsentSerializedData[n:]
			b = b[n:]
			t += n
		}
	}

	flushUnsent()
	for len(b) > 0 && err == nil {
		if len(e.unprocessedData) == 0 {
			tmp := make([]byte, originalblen)
			n, err = e.f.Read(tmp)
			e.unprocessedData = tmp[:n]
		}
		k := min(len(empty), len(e.unprocessedData))
		slice := e.unprocessedData[:k]
		e.unprocessedData = e.unprocessedData[k:]
		if len(slice) == 0 {
			if !flushNonSparse() {
				flushSparse()
			}
		} else if len(slice) == len(empty) && bytes.Compare(slice, empty[:]) == 0 {
			flushNonSparse()
			e.unsentSparseBlocks += 1
		} else {
			flushSparse()
			e.unsentNonSparseData = append(e.unsentNonSparseData, slice...)
		}
		if len(e.unsentNonSparseData) >= len(b) {
			flushNonSparse()
		}
		flushUnsent()
	}
	return t, err
}

type SparseDecoder struct {
	f               io.WriteSeeker
	p               uint64
	unprocessedData []byte
	fd              int
	wroteSparse     int64
}

func NewSparseDecoder(f io.WriteSeeker) *SparseDecoder {
	return &SparseDecoder{
		f:  f,
		p:  0,
		fd: getFd(f),
	}
}

func (e *SparseDecoder) Write(b []byte) (t int, err error) {

	var n int

	// Allocate buffer.  This will not be allocated on every loop.
	var encodedLength [8]byte

	e.unprocessedData = append(e.unprocessedData, b...)
	t += len(b)

	length := e.p
	for len(e.unprocessedData) >= 8 {
		// Read and parse length from input file.
		if e.p == 0 {
			var isSparse bool
			copy(encodedLength[:], e.unprocessedData)
			e.unprocessedData = e.unprocessedData[8:]
			header := binary.BigEndian.Uint64(encodedLength[:])
			if isSparse, length = flagIsSparse(header); length == 0 {
				return t, ErrCorrupted
			}
			if isSparse {
				// Seek on output file.
				byteslen := 512 * int64(length)
				e.wroteSparse += byteslen
				_, err = e.f.Seek(byteslen-1, 1)
				if err != nil {
					break
				}
				n, err = e.f.Write([]byte{0})
				if err != nil {
					break
				}
				continue
			}
		}
		// Write as much of the data as possible.
		sz := min(len(e.unprocessedData), int(length))
		n, err = e.f.Write(e.unprocessedData[:sz])
		length -= uint64(n)
		e.unprocessedData = e.unprocessedData[n:]
		if err != nil {
			break
		}
		if e.wroteSparse > 0 && e.fd > 0 {
			var pos int64
			pos, err = e.f.Seek(0, 1)
			if err != nil {
				break
			}
			pos = pos - e.wroteSparse - int64(n)
			err = syscall.Fallocate(e.fd, FALLOC_ERASE, pos, e.wroteSparse)
			if err != nil && err != syscall.ENOSYS && err != syscall.EOPNOTSUPP {
				break
			}
			e.wroteSparse = 0
		}
		e.p = length
	}
	return t, err
}
