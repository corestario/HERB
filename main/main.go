package main

import (
	"fmt"

	"github.com/dgamingfoundation/Herb/elgamal"
	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/group/nist"
)

func main() {
	suite := nist.NewBlakeSHA256P256()
	t := 4
	n := 10
	parties, err := elgamal.DKG(suite, n, t)
	if err != nil {
		println("DKG Error")
		println(err)
		return
	}
	participants := make([]elgamal.Participant, n)
	for i, p := range parties {
		keyShare, err := p.DistKeyShare()
		if err != nil {
			println(err)
			return
		}
		participants[i].ID = 1
		participants[i].PartialKey = keyShare.PriShare().V
		participants[i].CommonKey = keyShare.Public()
	}
	allC := make([]elgamal.Ciphertext, len(parties))
	// realM for check
	realM := suite.Point().Null()
	var Mi kyber.Point
	for i, p := range participants {
		m := []byte("NEJOPKA")
		allC[i], Mi = p.Encrypt(suite, m)
		realM = suite.Point().Add(realM, Mi)
	}
	C := elgamal.AggregateCiphertext(suite, allC)
	D := make([]kyber.Point, t)
	for i := 0; i < t; i++ {
		D[i] = participants[i].PartialDecrypt(suite, C)
	}
	randM := elgamal.Decrypt(suite, C, D, t, n)
	fmt.Println(randM.Equal(realM))

}
