// Copyright (c) 2019 Anton Semjonov
// Licensed under the MIT License

package main

import (
	"fmt"

	"github.com/ansemjo/ascon"
)

func main() {

	// plaintext and associated data
	plaintext := []byte("Hello, World!")
	associated := []byte("ascon")

	// keying
	nonce := []byte("0000000000000000")
	key := []byte("0000000000000000")

	fmt.Printf("%s\n", plaintext)

	a, err := ascon.New(key)
	if err != nil {
		panic("failed aead init")
	}

	c := a.Seal(nil, nonce, plaintext, associated)
	fmt.Printf("%#x\n", c)

	p, err := a.Open(nil, nonce, c, associated)
	if err != nil {
		panic("decryption failure: " + err.Error())
	}
	fmt.Printf("%s\n", p)

	p2, err := a.Open(nil, nonce, c[:len(c)-1], associated)
	if err != nil {
		panic("decryption failure: " + err.Error())
	}
	fmt.Printf("%s\n", p2)

}
