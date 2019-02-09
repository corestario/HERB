package point

import (
	"crypto/elliptic"
	"math/big"
)

//Curve handles point at infinity in a correct way
type Curve struct {
	elliptic.Curve
}

func (curve Curve) IsOnCurve(x, y *big.Int) bool {
	if IsPointAtInfinity(curve, x, y) {
		return true
	}

	return curve.Curve.IsOnCurve(x, y)
}
