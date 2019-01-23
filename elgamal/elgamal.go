package elgamal

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

//DKG is n-n distributed key generation protocol
func DKG(curve elliptic.Curve, n int) []Participant {
	parties := make([]Participant, n)
	for i := range parties {
		//each participant generates partial key
		parties[i] = NewParticipant(curve)
	}

	//then each party publishes partialKey.publicKey and everyone knows the public key of i-th participant
	partialPublicKeys := make([]Point, n)
	for i := range parties {
		partialPublicKeys[i] = parties[i].PartialKey.PublicKey
	}

	//each participant generates common public key from partial keys
	for i := range parties {
		parties[i].CommonKey = AggregateKeysToPoint(curve, partialPublicKeys)
	}

	return parties
}

//AggregateKeysToPoint recovers common public key from partial keys of participants
func AggregateKeysToPoint(curve elliptic.Curve, keys []Point) Point {
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

//Proofs currently not in use

//ProofDLK creates discrete logarithm knowledge proof for a = xG
func ProofDLK(ep *elliptic.CurveParams, pointA Point, x *big.Int) (ZKproof, Point) {
	w := randBigInt(ep)
	wBytes := w.Bytes()

	var pointH Point
	pointH.x, pointH.y = ep.ScalarMult(ep.Gx, ep.Gy, wBytes)

	var dlk ZKproof
	dlk.E = pointsProof(Point{ep.Gx, ep.Gy}, pointA, pointH)
	mul := new(big.Int).Mul(x, dlk.E)
	dlk.Z = new(big.Int).Sub(w, mul)

	return dlk, pointA
}

//VerifyDLK verify discrete logarithm knowledge proof for a = xG
func VerifyDLK(ep *elliptic.CurveParams, dl ZKproof, pointA Point) bool {
	var pointH, pointTemp1, pointTemp2 Point

	negZ := new(big.Int).Mod(dl.Z, ep.N)

	pointTemp1.x, pointTemp1.y = ep.ScalarMult(ep.Gx, ep.Gy, negZ.Bytes())
	pointTemp2.x, pointTemp2.y = ep.ScalarMult(pointA.x, pointA.y, dl.E.Bytes())

	pointH.x, pointH.y = ep.Add(pointTemp1.x, pointTemp1.y, pointTemp2.x, pointTemp2.y)

	proof := pointsProof(Point{ep.Gx, ep.Gy}, pointA, pointH)

	return proof.Cmp(dl.E) == 0
}

func ProofDLE(ep *elliptic.CurveParams, pointY, pointT, pointZ Point, x *big.Int) (ZKproof, Point, Point) {
	w := randBigInt(ep)
	wBytes := w.Bytes()

	var pointA1, pointA2 Point
	var mul *big.Int
	pointA1.x, pointA1.y = ep.ScalarMult(pointT.x, pointT.y, wBytes)
	pointA2.x, pointA2.y = ep.ScalarMult(ep.Gx, ep.Gy, wBytes)

	var dle ZKproof
	dle.E = pointsProof(pointY, pointZ, pointA1, pointA2)
	mul = new(big.Int).Mul(x, dle.E)
	dle.Z = new(big.Int).Sub(w, mul)

	return dle, pointY, pointZ
}

func VerifyDLE(ep *elliptic.CurveParams, dl ZKproof, pointY, pointT, pointZ Point) bool {
	var pointA1, pointA2, pointTemp1, pointTemp2 Point

	negz := new(big.Int).Mod(dl.Z, ep.N)
	pointTemp1.x, pointTemp1.y = ep.ScalarMult(pointT.x, pointT.y, negz.Bytes())
	pointTemp2.x, pointTemp2.y = ep.ScalarMult(pointY.x, pointY.y, dl.E.Bytes())

	pointA1.x, pointA1.y = ep.Add(pointTemp1.x, pointTemp1.y, pointTemp2.x, pointTemp2.y)

	pointTemp1.x, pointTemp1.y = ep.ScalarMult(ep.Gx, ep.Gy, negz.Bytes())
	pointTemp2.x, pointTemp2.y = ep.ScalarMult(pointZ.x, pointZ.y, dl.E.Bytes())

	pointA2.x, pointA2.y = ep.Add(pointTemp1.x, pointTemp1.y, pointTemp2.x, pointTemp2.y)

	proof := pointsProof(pointY, pointZ, pointA1, pointA2)

	return proof.Cmp(dl.E) == 0
}

func pointsProof(points ...Point) *big.Int {
	e := sha256.New()

	for _, point := range points {
		e.Write(point.x.Bytes())
		e.Write(point.y.Bytes())
	}

	pointsHash := e.Sum(nil)
	return new(big.Int).SetBytes(pointsHash)
}

var getRandom = rand.Int

//randBigInt creates big random value in the Fp - curve's field
func randBigInt(curve elliptic.Curve) *big.Int {
	max := curve.Params().P
	y, _ := getRandom(rand.Reader, max)
	//fixme we need to handle this err value somehow
	return y
}
