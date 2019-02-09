package elgamal

import (
	"crypto/elliptic"
	"crypto/sha256"
	"github.com/dgamingfoundation/HERB/point"
	"github.com/dgamingfoundation/HERB/rand"
	"math/big"
)

//ZKproof represents proof of discrete logarithm knowledge (DLK) or
//discrete logarithm equality (DLE).
type ZKproof struct {
	E *big.Int
	Z *big.Int
}

//Equal compares two proofs and returns true if they are equal
func (z ZKproof) Equal(z1 ZKproof) bool {
	return z.E.Cmp(z1.E) == 0 && z.Z.Cmp(z1.Z) == 0
}

//Proofs currently not in use

//ProofDLK creates discrete logarithm knowledge proof for a = xG
func ProofDLK(ep *elliptic.CurveParams, pointA point.Point, x *big.Int) (ZKproof, point.Point) {
	w := rand.RandEllipticKey(ep)
	wBytes := w.Bytes()

	var pointH point.Point
	pointH.Set(ep.ScalarMult(ep.Gx, ep.Gy, wBytes))

	var dlk ZKproof
	dlk.E = hashPoints(point.Point{ep.Gx, ep.Gy}, pointA, pointH)
	mul := new(big.Int).Mul(x, dlk.E)
	dlk.Z = new(big.Int).Sub(w, mul)

	return dlk, pointA
}

//VerifyDLK verify discrete logarithm knowledge proof for a = xG
func VerifyDLK(ep *elliptic.CurveParams, dl ZKproof, pointA point.Point) bool {
	var pointH, pointTemp1, pointTemp2 point.Point

	negZ := new(big.Int).Mod(dl.Z, ep.N)

	pointTemp1.Set(ep.ScalarMult(ep.Gx, ep.Gy, negZ.Bytes()))
	pointTemp2.Set(ep.ScalarMult(pointA.GetX(), pointA.GetY(), dl.E.Bytes()))

	pointH.Set(ep.Add(pointTemp1.GetX(), pointTemp1.GetY(), pointTemp2.GetX(), pointTemp2.GetY()))

	proof := hashPoints(point.Point{ep.Gx, ep.Gy}, pointA, pointH)

	return proof.Cmp(dl.E) == 0
}

//ProofDLE creates discrete logarithm equality proof for pointY = x*pointT, pointZ = x * G
func ProofDLE(ep *elliptic.CurveParams, pointY, pointT, pointZ point.Point, x *big.Int) (ZKproof, point.Point, point.Point) {
	w := rand.RandEllipticKey(ep)
	wBytes := w.Bytes()

	var pointA1, pointA2 point.Point
	var mul *big.Int
	pointA1.Set(ep.ScalarMult(pointT.GetX(), pointT.GetY(), wBytes))
	pointA2.Set(ep.ScalarMult(ep.Gx, ep.Gy, wBytes))

	var dle ZKproof
	dle.E = hashPoints(pointY, pointZ, pointA1, pointA2)
	mul = new(big.Int).Mul(x, dle.E)
	dle.Z = new(big.Int).Sub(w, mul)

	return dle, pointY, pointZ
}

//VerifyDLE verify discrete logarithm equality proof for pointY = x*pointT, pointZ = x * G
func VerifyDLE(ep *elliptic.CurveParams, dl ZKproof, pointY, pointT, pointZ point.Point) bool {
	var pointA1, pointA2, pointTemp1, pointTemp2 point.Point

	negz := new(big.Int).Mod(dl.Z, ep.N)
	pointTemp1.Set(ep.ScalarMult(pointT.GetX(), pointT.GetY(), negz.Bytes()))
	pointTemp2.Set(ep.ScalarMult(pointY.GetX(), pointY.GetY(), dl.E.Bytes()))

	pointA1.Set(ep.Add(pointTemp1.GetX(), pointTemp1.GetY(), pointTemp2.GetX(), pointTemp2.GetY()))

	pointTemp1.Set(ep.ScalarMult(ep.Gx, ep.Gy, negz.Bytes()))
	pointTemp2.Set(ep.ScalarMult(pointZ.GetX(), pointZ.GetY(), dl.E.Bytes()))

	pointA2.Set(ep.Add(pointTemp1.GetX(), pointTemp1.GetY(), pointTemp2.GetX(), pointTemp2.GetY()))

	proof := hashPoints(pointY, pointZ, pointA1, pointA2)

	return proof.Cmp(dl.E) == 0
}

func hashPoints(points ...point.Point) *big.Int {
	e := sha256.New()

	for _, point := range points {
		e.Write(point.GetX().Bytes())
		e.Write(point.GetY().Bytes())
	}

	pointsHash := e.Sum(nil)
	return new(big.Int).SetBytes(pointsHash)
}
