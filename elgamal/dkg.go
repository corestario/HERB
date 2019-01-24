package elgamal

import "crypto/elliptic"

//DKG is n-n distributed key generation protocol
func DKG(curve elliptic.Curve, n int) []Participant {
	parties := make([]Participant, n)
	for i := range parties {
		//each participant generates partial key
		parties[i] = NewParticipant(curve, i)
	}

	//then each party publishes partialKey.publicKey and everyone knows the public key of i-th participant
	partialPublicKeys := make([]Point, n)
	for i := range parties {
		partialPublicKeys[i] = parties[i].PartialKey.PublicKey
	}

	//each participant generates common public key from partial keys
	for i := range parties {
		parties[i].CommonKey = RecoverPoint(curve, partialPublicKeys)
	}

	return parties
}
