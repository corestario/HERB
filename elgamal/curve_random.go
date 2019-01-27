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

//randEllipticKey creates big random value in the {2, .., |G|-1}, where G is choosen group of elliptic curve points
func randEllipticKey(curve elliptic.Curve) *big.Int {
	max := big.NewInt(1)
	max.Sub(curve.Params().N, big.NewInt(2))
	y, _ := getRandom(rand.Reader, max)
	y.Add(y, big.NewInt(2))
	//fixme we need to handle this err value somehow
	return y
}
