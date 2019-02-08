package elgamal

import (
	"crypto/elliptic"
	"errors"
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

func FromCoordinates(curve elliptic.Curve, x, y *big.Int) (Point, error) {
	if !curve.IsOnCurve(x, y) {
		return Point{}, fmt.Errorf("point(%s, %s) is not on the curve: %v", x.String(), y.String(), curve.Params())
	}
	return Point{x, y}, nil
}

//RecoverPoint recovers common public key from partial keys of participants
func RecoverPoint(curve elliptic.Curve, keys []Point) (Point, error) {
	if len(keys) == 0 {
		return PointAtInfinity(curve), errors.New("more than 0 partial keys should be given")
	}

	result := keys[0]
	for i := 1; i < len(keys); i++ {
		result = result.Add(curve, keys[i])
	}

	return result, nil
}

//X coordinate of the point p
func (p Point) X() *big.Int {
	return new(big.Int).Set(p.x)
}

//Y coordinate of the point p
func (p Point) Y() *big.Int {
	return new(big.Int).Set(p.y)
}

func (p Point) Add(curve elliptic.Curve, p2 Point) (point Point) {
	point.x, point.y = curve.Params().Add(p.x, p.y, p2.x, p2.y)
	return
}

func (p Point) Neg(curve elliptic.Curve) Point {
	y := big.NewInt(1)
	x := big.NewInt(1)
	x.Set(p.x)
	y.Neg(p.y)
	y.Add(y, curve.Params().P)
	y.Mod(y, curve.Params().P)
	return Point{x, y}
}

func (p Point) ScalarMult(curve elliptic.Curve, t *big.Int) Point {
	x, y := curve.ScalarMult(p.x, p.y, t.Bytes())
	point := Point{x, y}
	return point
}

func (p Point) Sub(curve elliptic.Curve, p2 Point) (point Point) {
	return p.Add(curve, p2.Neg(curve))
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
	pointTemp := ct.pointA.ScalarMult(curve, x)
	pointTemp.y = pointTemp.y.Neg(pointTemp.y)

	//M = b - xA
	return ct.pointB.Add(curve, pointTemp)
}
