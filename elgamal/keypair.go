package elgamal

import (
	"math/big"
)

//KeyPair contains secret and public keys for ElGamal cryptosystem
type KeyPair struct {
	SecretKey *big.Int
	PublicKey Point
}

func (kp KeyPair) IsEqual(kp1 KeyPair) bool {
	return kp.SecretKey.Cmp(kp1.SecretKey) == 0 && kp.PublicKey.IsEqual(kp1.PublicKey)
}