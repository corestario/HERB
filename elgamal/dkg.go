package elgamal

import (
	"crypto/elliptic"

	"github.com/dgamingfoundation/HERB/point"
)

//DKG is n-n distributed key generation protocol
func DKG(curve elliptic.Curve, n int) ([]Participant, error) {
	parties := make([]Participant, n)
	for i := range parties {
		//each participant generates partial key
		parties[i] = NewParticipant(curve, i)
	}

	//then each party publishes partialKey.publicKey and everyone knows the public key of i-th participant
	partialPublicKeys := make([]point.Point, n)
	for i := range parties {
		partialPublicKeys[i] = parties[i].PartialKey.PublicKey
	}

	//each participant generates common public key from partial keys
	var err error
	for i := range parties {
		parties[i].CommonKey, err = point.Recover(curve, partialPublicKeys)
		if err != nil {
			return nil, err
		}
	}

	return parties, nil
}
