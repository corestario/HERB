package elgamal

import (
	"math/big"

	"github.com/dgamingfoundation/HERB/point"
)

//KeyPair contains secret and public keys for ElGamal cryptosystem
type KeyPair struct {
	SecretKey *big.Int
	PublicKey point.Point
}

//IsEqual compares two key pairs and returns true if their secret and public keys are match
func (kp KeyPair) IsEqual(kp1 KeyPair) bool {
	return kp.SecretKey.Cmp(kp1.SecretKey) == 0 && kp.PublicKey.IsEqual(kp1.PublicKey)
}
