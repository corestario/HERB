package elgamal

import (
	"math/big"
)

//KeyPair contains secret and public keys for ElGamal cryptosystem
type KeyPair struct {
	SecretKey *big.Int
	PublicKey Point
}

//Equal compares two key pairs and returns true if their secret and public keys are match
func (kp KeyPair) Equal(kp1 KeyPair) bool {
	return kp.SecretKey.Cmp(kp1.SecretKey) == 0 && kp.PublicKey.Equal(kp1.PublicKey)
}
