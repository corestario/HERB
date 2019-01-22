package main

import (
	"crypto/elliptic"
	"fmt"

	eg "./elgamal"
)

func main() {
	//number of our participants (validators set)
	n := 3
	// creating elliptic curve
	E := elliptic.P256()

	//generating key
	parties := eg.DKG(E, n)

	//Any system user generates some message, enctrypts and publishes it
	//We use our validators set (parties) just for example
	publishedCiphertextes := make([]eg.Ciphertext, n)

	var newMessage eg.Point
	for i := range publishedCiphertextes {
		newMessage = eg.GeneratePoint(E)
		publishedCiphertextes[i] = parties[i].Encrypt(E, newMessage)
	}
	//aggregate all ciphertextes
	commonCiphertext := eg.AggregateCiphertext(E, publishedCiphertextes)
	//fmt.Println(eg.VerifyDLK(Ep, Cdlk, a))

	//decrypt the random
	decryptParts := make([]eg.Point, n)
	for i := range parties {
		decryptParts[i] = parties[i].PartialDecrypt(E, commonCiphertext)
	}
	newM := eg.DecryptFromShares(E, decryptParts, commonCiphertext)
	fmt.Println(newM.X(), newM.Y())
}
