package blake2

import (
	// #cgo CFLAGS: -O3 -static
	// #cgo LDFLAGS: -l:blake2b.lib
	// #include <stddef.h>
	// #include <stdint.h>
	// #include "app/include/blake2b.h"
	"C"
	"hash"
)

func init() {
	if C.blake2b_startup() != 0 {
		panic("blake2: unable to start")
	}
}

func NewBlake2B() hash.Hash {
	return NewBlake2BKeyed(nil)
}

func NewBlake2BKeyed(key []byte) hash.Hash {
	if len(key) > 32 {
		panic("blake2: key too long")
	}
	d := &digest{
		key: key,
	}
	d.Reset()
	return d
}

type digest struct {
	state *C.blake2b_state
	key   []byte
}

func (*digest) BlockSize() int {
	return 128
}

func (d *digest) Size() int {
	return 64
}

func (d *digest) Reset() {
	d.state = new(C.blake2b_state)
	if len(d.key) > 0 {
		C.blake2b_keyed_init(d.state, (*C.uchar)(&d.key[0]), C.size_t(len(d.key)))
	} else {
		C.blake2b_init(d.state)
	}
}

func (d *digest) Sum(buf []byte) []byte {
	digest := make([]byte, 64)
	C.blake2b_final(d.state, (*C.uchar)(&digest[0]))
	return append(buf, digest...)
}

func (d *digest) Write(buf []byte) (int, error) {
	if len(buf) > 0 {
		C.blake2b_update(d.state, (*C.uchar)(&buf[0]), C.size_t(len(buf)))
	}
	return len(buf), nil
}

func Hash(buf []byte) []byte {
	hash := make([]byte, 64)
	C.blake2b((*C.uchar)(&hash[0]), (*C.uchar)(&buf[0]), C.size_t(len(buf)))
	return hash
}

func HashKeyed(key, buf []byte) []byte {
	if len(key) > 32 {
		panic("blake2: key too long")
	}
	hash := make([]byte, 64)
	C.blake2b_keyed((*C.uchar)(&hash[0]), (*C.uchar)(&buf[0]), C.size_t(len(buf)), (*C.uchar)(&key[0]), C.size_t(len(key)))
	return hash
}
