package simplenaclcrypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"io/ioutil"
	"os"
	"testing"
)

func tcopy(t *testing.T, b []byte) (int64, []byte, error) {
	i := bytes.NewBuffer(b)
	s := NewSparseEncoder(i)
	o := tmpFile(t)
	defer func() { os.Remove(o.Name()) }()
	d := NewSparseDecoder(o)
	n, err := io.Copy(d, s)
	o.Seek(0, 0)
	buf, err2 := ioutil.ReadAll(o)
	if err2 != nil {
		t.Fatalf("%s: err != nil: %s", err)
	}
	return n, buf, err
}

func tmpFile(t *testing.T) *os.File {
	o, err := ioutil.TempFile("", "simplenaclcryptotest")
	if err != nil {
		t.Fatalf("err != nil: %s", err)
	}
	return o
}

func same(t *testing.T, d string, actual []byte, exp []byte) {
	if bytes.Compare(actual, exp) != 0 {
		t.Errorf("%s: %v != %v", d, actual, exp)
	}
}

func isnil(t *testing.T, d string, err error) {
	if err != nil {
		t.Errorf("%s: err != nil: %s", d, err)
	}
}

func lenis(t *testing.T, d string, l int64, exp int64) {
	if l != exp {
		t.Errorf("%s: %d != %d", d, l, exp)
	}
}

func bunchadata(t *testing.T, header []byte, s int, trailer []byte) []byte {
	buf := make([]byte, s)
	n, err := rand.Reader.Read(buf)
	if err != nil || n != s {
		t.Fatalf("cannot make buncha data: %s %d %d", err, s, n)
	}
	return append(append(header, buf...), trailer...)
}

func TestSparseCases(t *testing.T) {
	block := make([]byte, 512)
	for _, c := range []struct {
		desc   string
		exp    []byte
		explen int64
	}{
		{"zero byte", []byte{}, 0},
		{"one byte", []byte{1}, 9},
		{"one zero block", block, 8},
		{"511 bytes", make([]byte, 511), 519},
		{"one zero block plus one byte", make([]byte, 513), 8 + 9},
		{"1 MB", make([]byte, 1024*1024), 8},
		{"buncha data", bunchadata(t, []byte{}, 2378595, []byte{}), 2378595 + (2378595 / 32768 * 8) + 8},
		{"buncha data starting with empty block", bunchadata(t, block, 2378595, []byte{}), 2378595 + (2378595 / 32768 * 8) + 8 + 8},
		{"buncha data surrounded with empty blocks", bunchadata(t, block, 2378595, block), 8 + (2378595 / 32768 * 8) + 2378595 + 8 + 512},
		{"buncha byte-aligned data surrounded with empty blocks", bunchadata(t, block, 1048576, block), 1048848},
	} {
		n, data, err := tcopy(t, c.exp)
		isnil(t, c.desc, err)
		same(t, c.desc, data, c.exp)
		lenis(t, c.desc, n, c.explen)
	}
}
