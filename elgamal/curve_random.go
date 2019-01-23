package elgamal

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

//needed for tests
var getRandom = rand.Int

//randBigInt creates big random value in the Fp - curve's field
func randBigInt(curve elliptic.Curve) *big.Int {
	max := curve.Params().P
	y, _ := getRandom(rand.Reader, max)
	//fixme we need to handle this err value somehow
	return y
}
