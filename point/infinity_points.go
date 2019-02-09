package point

import (
	"crypto/elliptic"
	"math/big"
	"sync"
)

//PointAtInfinity returns neutral element of the elliptic curve group
func PointAtInfinity(curve elliptic.Curve) (pointInf Point) {
	return infPoints.get(curve)
}

//IsPointAtInfinity check x,y coordinates are point-at-infinity on the curve or not
func IsPointAtInfinity(curve elliptic.Curve, x, y *big.Int) bool {
	pInf := PointAtInfinity(curve)
	return x.Cmp(pInf.X) == 0 && y.Cmp(pInf.Y) == 0
}

//pointAtInfinity calculates neutral element of the elliptic curve group
func pointAtInfinity(curve elliptic.Curve) (pointInf Point) {
	ep := curve.Params()
	n := ep.N
	pointInf.Set(ep.ScalarMult(ep.Gx, ep.Gy, n.Bytes()))
	return
}

var infPoints = pointStorage{
	m: map[string]Point{
		elliptic.P256().Params().Name: pointAtInfinity(elliptic.P256()),
		elliptic.P384().Params().Name: pointAtInfinity(elliptic.P384()),
		elliptic.P521().Params().Name: pointAtInfinity(elliptic.P521()),
	},
}

type pointStorage struct {
	sync.RWMutex
	m map[string]Point
}

func (p *pointStorage) get(curve elliptic.Curve) Point {
	p.RLock()
	point, ok := p.m[curve.Params().Name]
	p.RUnlock()

	if ok {
		return point
	}

	point = pointAtInfinity(curve)

	p.Lock()
	p.m[curve.Params().Name] = point
	p.Unlock()

	return point
}
