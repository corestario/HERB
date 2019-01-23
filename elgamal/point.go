package elgamal

import (
	"crypto/elliptic"
	"math/big"
)

//Point represents points on the elliptic curve P = (x, y)
//Open messages are elliptic curve's points.
type Point struct {
	x *big.Int
	y *big.Int
}

//NewPoint allows to generate random point on the elliptic curve E
func NewPoint(curve elliptic.Curve) (pointM Point) {
	ep := curve.Params()
	y := randBigInt(ep)
	pointM.x, pointM.y = ep.ScalarMult(ep.Gx, ep.Gy, y.Bytes())
	return
}

//X coordinate of the point p
func (p Point) X() big.Int {
	return *p.x
}

//Y coordinate of the point p
func (p Point) Y() big.Int {
	return *p.y
}

func (p Point) add(curve elliptic.Curve, p2 Point) (point Point) {
	point.x, point.y = curve.Params().Add(p.x, p.y, p2.x, p2.y)
	return
}

func (p Point) neg() Point {
	p.y = p.y.Neg(p.y)
	return p
}

func (p Point) scalarMult(curve elliptic.Curve, t *big.Int) (point Point) {
	point.x, point.y = curve.ScalarMult(p.x, p.y, t.Bytes())
	return
}

//Decrypt the ciphertext C with the key x
//Currently not in use
func decrypt(curve elliptic.Curve, ct Ciphertext, x *big.Int) Point {
	pointTemp := ct.pointA.scalarMult(curve, x)
	pointTemp.y = pointTemp.y.Neg(pointTemp.y)

	//M = b - xA
	return ct.pointB.add(curve, pointTemp)
}
