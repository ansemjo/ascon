package main

// #cgo CFLAGS: -std=c99 -Wall
// #include "api.h"
// #include "crypto_aead.h"
import "C"
import (
	"fmt"
	"reflect"
	"unsafe"
)

func main() {

	// plaintext and associated data
	plaintext := []byte("Hello, World!")
	associatedData := []byte("ascon")

	// keying
	npub := []byte("0123456701234567")
	key := []byte("0123456789abcdef")

	fmt.Printf("%s\n", plaintext)

	c := ascon_encrypt(plaintext, associatedData, npub, key)
	fmt.Printf("%#x\n", c)

}

func ascon_encrypt(pt, ad, nonce, key []byte) (ct []byte) {

	ptHeader := (*reflect.SliceHeader)(unsafe.Pointer(&pt))
	adHeader := (*reflect.SliceHeader)(unsafe.Pointer(&ad))
	nonceHeader := (*reflect.SliceHeader)(unsafe.Pointer(&nonce))
	keyHeader := (*reflect.SliceHeader)(unsafe.Pointer(&key))

	ct = make([]byte, ptHeader.Len+C.CRYPTO_KEYBYTES)
	ctHeader := (*reflect.SliceHeader)(unsafe.Pointer(&ct))

	C.crypto_aead_encrypt(
		(*C.uchar)(unsafe.Pointer(ctHeader.Data)), (*C.ulonglong)(unsafe.Pointer(&ctHeader.Len)),
		(*C.uchar)(unsafe.Pointer(ptHeader.Data)), C.ulonglong(ptHeader.Len),
		(*C.uchar)(unsafe.Pointer(adHeader.Data)), C.ulonglong(adHeader.Len),
		(*C.uchar)(unsafe.Pointer(nil)),
		(*C.uchar)(unsafe.Pointer(nonceHeader.Data)),
		(*C.uchar)(unsafe.Pointer(keyHeader.Data)),
	)

	return
}
