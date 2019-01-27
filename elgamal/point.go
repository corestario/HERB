package elgamal

import (
	"crypto/elliptic"
	"fmt"
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
	y := randEllipticKey(ep)
	pointM.x, pointM.y = ep.ScalarMult(ep.Gx, ep.Gy, y.Bytes())
	return
}

//PointAtInfinity returns neutral element of the elliptic curve group
func PointAtInfinity(curve elliptic.Curve) (pointInf Point) {
	ep := curve.Params()
	n := ep.N
	pointInf.x, pointInf.y = ep.ScalarMult(ep.Gx, ep.Gy, n.Bytes())
	return
}

//RecoverPoint recovers common public key from partial keys of participants
func RecoverPoint(curve elliptic.Curve, keys []Point) Point {
	if len(keys) == 0 {
		//fixme: is it a correct return value?
		return Point{}
	}

	result := keys[0]
	for i := 1; i < len(keys); i++ {
		result = result.add(curve, keys[i])
	}

	return result
}

//X coordinate of the point p
func (p Point) X() *big.Int {
	return new(big.Int).Set(p.x)
}

//Y coordinate of the point p
func (p Point) Y() *big.Int {
	return new(big.Int).Set(p.y)
}

func (p Point) add(curve elliptic.Curve, p2 Point) (point Point) {
	point.x, point.y = curve.Params().Add(p.x, p.y, p2.x, p2.y)
	return
}

func (p Point) neg() Point {
	p.y.Set(p.y.Neg(p.y))
	return p
}

func (p Point) scalarMult(curve elliptic.Curve, t *big.Int) Point {
	x, y := curve.ScalarMult(p.x, p.y, t.Bytes())
	point := Point{x, y}
	return point
}

func (p Point) sub(curve elliptic.Curve, p2 Point) (point Point) {
	return p.add(curve, p2.neg())
}

func (p Point) String() string {
	return fmt.Sprintf("Point{%s, %s}", p.x, p.y)
}

//IsEqual compares two points and returns true if their x and y-coordinates are match
func (p Point) IsEqual(p1 Point) bool {
	return p.x.Cmp(p1.x) == 0 && p.y.Cmp(p1.y) == 0
}

//Decrypt the ciphertext C with the key x
//Currently not in use
func decrypt(curve elliptic.Curve, ct Ciphertext, x *big.Int) Point {
	pointTemp := ct.pointA.scalarMult(curve, x)
	pointTemp.y = pointTemp.y.Neg(pointTemp.y)

	//M = b - xA
	return ct.pointB.add(curve, pointTemp)
}
