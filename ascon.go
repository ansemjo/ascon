// Package ascon binds to the C reference implementation of
// Ascon-128 v1.2 from the final CAESAR portfolio and implements
// the cipher.AEAD interface.
// https://ascon.iaik.tugraz.at/specification.html
package ascon

// #cgo CFLAGS: -Wall -O2
// #include "crypto_aead.h"
import "C"
import (
	"crypto/cipher"
	"errors"
	"reflect"
	"unsafe"
)

// Expected key, nonce and authentication tag overhead lengths
const (
	KeySize   = 16
	NonceSize = 16
	Overhead  = 16
)

type ascon struct {
	key []byte
}

// generic error when decryption fails
var errAuth = errors.New("ascon: message authentication failed")

// New returns a new Ascon-128 AEAD that uses the given 128-bit key.
func New(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("ascon: bad key length")
	}
	return &ascon{key}, nil
}

func (c *ascon) NonceSize() int {
	return NonceSize
}

func (c *ascon) Overhead() int {
	return Overhead
}

// Seal encrypts and authenticates the given plaintext.
func (c *ascon) Seal(dst, nonce, plaintext, associated []byte) []byte {

	if len(nonce) != NonceSize {
		panic("ascon: bad nonce length")
	}

	plaintextHeader := (*reflect.SliceHeader)(unsafe.Pointer(&plaintext))
	associatedHeader := (*reflect.SliceHeader)(unsafe.Pointer(&associated))
	nonceHeader := (*reflect.SliceHeader)(unsafe.Pointer(&nonce))
	keyHeader := (*reflect.SliceHeader)(unsafe.Pointer(&c.key))

	dst = make([]byte, plaintextHeader.Len+Overhead)
	dstHeader := (*reflect.SliceHeader)(unsafe.Pointer(&dst))

	ret := C.crypto_aead_encrypt(
		(*C.uchar)(unsafe.Pointer(dstHeader.Data)), (*C.ulonglong)(unsafe.Pointer(&dstHeader.Len)),
		(*C.uchar)(unsafe.Pointer(plaintextHeader.Data)), C.ulonglong(plaintextHeader.Len),
		(*C.uchar)(unsafe.Pointer(associatedHeader.Data)), C.ulonglong(associatedHeader.Len),
		(*C.uchar)(unsafe.Pointer(nil)),
		(*C.uchar)(unsafe.Pointer(nonceHeader.Data)),
		(*C.uchar)(unsafe.Pointer(keyHeader.Data)),
	)

	if ret != 0 {
		panic("ascon: encryption failed")
	}

	return dst
}

// Open decrypts the given ciphertext and errors if authentication or
// decryption fails.
func (c *ascon) Open(dst, nonce, ciphertext, associated []byte) ([]byte, error) {

	if len(nonce) != NonceSize {
		panic("ascon: bad nonce length")
	}
	if len(ciphertext) < Overhead {
		return nil, errAuth
	}

	ciphertextHeader := (*reflect.SliceHeader)(unsafe.Pointer(&ciphertext))
	associatedHeader := (*reflect.SliceHeader)(unsafe.Pointer(&associated))
	nonceHeader := (*reflect.SliceHeader)(unsafe.Pointer(&nonce))
	keyHeader := (*reflect.SliceHeader)(unsafe.Pointer(&c.key))

	dst = make([]byte, ciphertextHeader.Len-Overhead)
	dstHeader := (*reflect.SliceHeader)(unsafe.Pointer(&dst))

	ret := C.crypto_aead_decrypt(
		(*C.uchar)(unsafe.Pointer(dstHeader.Data)), (*C.ulonglong)(unsafe.Pointer(&dstHeader.Len)),
		(*C.uchar)(unsafe.Pointer(nil)),
		(*C.uchar)(unsafe.Pointer(ciphertextHeader.Data)), C.ulonglong(ciphertextHeader.Len),
		(*C.uchar)(unsafe.Pointer(associatedHeader.Data)), C.ulonglong(associatedHeader.Len),
		(*C.uchar)(unsafe.Pointer(nonceHeader.Data)),
		(*C.uchar)(unsafe.Pointer(keyHeader.Data)),
	)

	if ret != 0 {
		return nil, errAuth
	}

	return dst, nil
}
