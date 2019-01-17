package main

import (
	"crypto/elliptic"
	"fmt"

	eg "github.com/SK0M0R0H/HERB/elgamal"
)

func main() {
	//number of our participants (validators set)
	n := 3
	// creating elliptic curve
	E := elliptic.P256()
	Ep := E.Params()
	//generating key
	parties := eg.DKG(E, n)
	//Any system user generates some message and publishes it
	//We use our validators set (parties) just for example
	publishedMessages := make([]eg.Point, n)
	for i := range publishedMessages {
		publishedMessages[i] = eg.GeneratePoint(E)
	}
	M := eg.GeneratePoint(E)
	//fmt.Println(M.x, M.y)
	fmt.Println(parties[0].CommonKey)
	C := parties[0].Encrypt(Ep, M)
	//fmt.Println(eg.VerifyDLK(Ep, Cdlk, A))
	decryptParts := make([]eg.Point, n)
	for i := range parties {
		decryptParts[i] = parties[i].PartialDecrypt(E, C)
	}
	//aggregating all parts
	decryptKey := decryptParts[0]
	for i := 1; i < n; i++ {
		decryptKey = decryptKey.Add(E, decryptParts[i])
	}
	//newM := C.B.Add(E, decryptKey.Neg())
	//fmt.Println(newM.X, newM.Y)

}
