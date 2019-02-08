package point

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/dgamingfoundation/HERB/rand"
)

//Point represents points on the elliptic curve P = (x, y)
//Open messages are elliptic curve's points.
type Point struct {
	X *big.Int
	Y *big.Int
}

//New allows to generate random point on the elliptic curve E
func New(curve elliptic.Curve) *Point {
	ep := curve.Params()
	y := rand.RandEllipticKey(ep)

	pointM := &Point{}
	pointM.Set(ep.ScalarMult(ep.Gx, ep.Gy, y.Bytes()))
	return pointM
}

func FromCoordinates(curve elliptic.Curve, x, y *big.Int) (Point, error) {
	expectedPoint := Point{x, y}
	if expectedPoint.IsPointAtInfinity(curve) {
		return Point{x, y}, nil
	}

	if !curve.IsOnCurve(x, y) {
		return Point{}, fmt.Errorf("point(%s, %s) is not on the curve: %v", x.String(), y.String(), curve.Params())
	}

	return expectedPoint, nil
}

//Recover recovers common public key from partial keys of participants
func Recover(curve elliptic.Curve, keys []Point) (Point, error) {
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
func (p Point) GetX() *big.Int {
	return new(big.Int).Set(p.X)
}

//Y coordinate of the point p
func (p Point) GetY() *big.Int {
	return new(big.Int).Set(p.Y)
}

//SetX coordinate of the point p
func (p *Point) SetX(x *big.Int) *Point {
	p.X = x
	return p
}

//SetY coordinate of the point p
func (p *Point) SetY(y *big.Int) *Point {
	p.Y = y
	return p
}

//Set coordinate of the point p
func (p *Point) Set(x, y *big.Int) *Point {
	p.SetX(x)
	p.SetY(y)
	return p
}

func (p Point) Add(curve elliptic.Curve, p2 Point) (point Point) {
	point.Set(curve.Params().Add(p.X, p.Y, p2.X, p2.Y))
	return
}

func (p Point) Neg(curve elliptic.Curve) Point {
	y := big.NewInt(1)
	x := big.NewInt(1)
	x.Set(p.X)
	y.Neg(p.Y)
	y.Add(y, curve.Params().P)
	y.Mod(y, curve.Params().P)
	return Point{x, y}
}

func (p Point) ScalarMult(curve elliptic.Curve, t *big.Int) Point {
	x, y := curve.ScalarMult(p.X, p.Y, t.Bytes())
	point := Point{x, y}
	return point
}

func (p Point) Sub(curve elliptic.Curve, p2 Point) (point Point) {
	return p.Add(curve, p2.Neg(curve))
}

func (p Point) String() string {
	return fmt.Sprintf("Point{%s, %s}", p.X, p.Y)
}

//IsEqual compares two points and returns true if their x and y-coordinates are match
func (p Point) IsEqual(p1 Point) bool {
	return p.X.Cmp(p1.X) == 0 && p.Y.Cmp(p1.Y) == 0
}

//IsPointAtInfinity check p is point-at-infinity on the curve or not
func (p Point) IsPointAtInfinity(curve elliptic.Curve) bool {
	return p.IsEqual(PointAtInfinity(curve))
}
