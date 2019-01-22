package elgamal

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

//Point represents points on the elliptic curve P = (x, y)
//Open messages are elliptic curve's points.
type Point struct {
	x *big.Int
	y *big.Int
}

//Ciphertext is usual ElGamal ciphertext C = (a, b)
//Here a, b - the elliptic curve's points
type Ciphertext struct {
	pointA Point
	pointB Point
}

//ZKproof represents proof of discrete logarithm knowledge (DLK) or
//discrete logarithm equality (DLE).
type ZKproof struct {
	E *big.Int
	Z *big.Int
}

//KeyPair contains secret and public keys for ElGamal cryptosystem
type KeyPair struct {
	SecretKey *big.Int
	PublicKey Point
}

//Participant of the random generation process
type Participant struct {
	PartialKey KeyPair
	CommonKey  Point
	ID         int
}

///////
//Point-related functions
///////

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

///////
//
///////

//randBigInt creates big random value in the Fp - curve's field
func randBigInt(curve elliptic.Curve) *big.Int {
	max := curve.Params().P
	y, _ := rand.Int(rand.Reader, max)
	//fixme we need to handle this err value somehow
	return y
}

//GeneratePoint allows to generate random point on the elliptic curve E
func GeneratePoint(curve elliptic.Curve) (pointM Point) {
	ep := curve.Params()
	y := randBigInt(ep)
	pointM.x, pointM.y = ep.ScalarMult(ep.Gx, ep.Gy, y.Bytes())
	return
}

//GenerateKeyPair return pair of secret and public key for the participant p.
func (p *Participant) GenerateKeyPair(curve elliptic.Curve) {
	ep := curve.Params()
	//secret key
	x := randBigInt(ep)
	//public key

	qx, qy := ep.ScalarMult(ep.Gx, ep.Gy, x.Bytes())
	keyPair := KeyPair{x, Point{qx, qy}}
	p.PartialKey = keyPair
}

//Encrypt return encrypted message M and proof of t
func (p Participant) Encrypt(curve elliptic.Curve, pointM Point) Ciphertext {
	ep := curve.Params()
	r := randBigInt(ep)

	var pointA, pointB Point
	//pointA = rG
	pointA.x, pointA.y = ep.ScalarMult(ep.Gx, ep.Gy, r.Bytes())

	//pointB = rQ + M
	pointB = p.CommonKey.scalarMult(ep, r).add(ep, pointM)

	//var dlk, A1 = ProofDLK(Ep, pointA, r)
	return Ciphertext{pointA, pointB}
}

//Decrypt the ciphertext C with the key x
//Currently not in use
func decrypt(curve elliptic.Curve, ct Ciphertext, x *big.Int) Point {
	pointTemp := ct.pointA.scalarMult(curve, x)
	pointTemp.y = pointTemp.y.Neg(pointTemp.y)

	//M = b - xA
	return ct.pointB.add(curve, pointTemp)
}

//DecryptFromShares takes decrypt parts (shares) from all participants and decrypt the ciphertext C
func DecryptFromShares(curve elliptic.Curve, shares []Point, ct Ciphertext) Point {
	if len(shares) == 0 {
		//fixme: is it a correct return value?
		return Point{}
	}

	//aggregating all parts
	decryptKey := shares[0]
	for i := 1; i < len(shares); i++ {
		decryptKey = decryptKey.add(curve, shares[i])
	}

	M := ct.pointB.add(curve, decryptKey.neg())
	return M
}

//IsValidCiphertext return true if both part of the ciphertext C on the curve E.
func IsValidCiphertext(ct Ciphertext, curve elliptic.Curve) bool {
	statement1 := curve.IsOnCurve(ct.pointA.x, ct.pointA.y)
	statement2 := curve.IsOnCurve(ct.pointB.x, ct.pointB.y)
	return statement1 && statement2
}

//AggregateCiphertext takes the set of ciphertextes parts:
//parts[0] = (A0, B0), ..., parts[n] = (An, Bn)
//and returns aggregated ciphertext C = (A1 + A2 + ... + An, B1 + B2 + ... + Bn)
func AggregateCiphertext(curve elliptic.Curve, parts []Ciphertext) Ciphertext {
	if len(parts) == 0 {
		//fixme: is it a correct return value?
		return Ciphertext{}
	}

	ct := Ciphertext{parts[0].pointA, parts[0].pointB}
	for i := 1; i < len(parts); i++ {
		ct.pointA = ct.pointA.add(curve, parts[i].pointA)
		ct.pointB = ct.pointB.add(curve, parts[i].pointB)
	}

	return ct
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

//PartialDecrypt returns share of the decryption key for the particular ciphertext C
func (p Participant) PartialDecrypt(curve elliptic.Curve, ct Ciphertext) (point Point) {
	point.x, point.y = curve.ScalarMult(ct.pointA.x, ct.pointA.y, p.PartialKey.SecretKey.Bytes())
	return
}

//Proofs currently not in use

//ProofDLK creates discrete logarithm knowledge proof for a = xG
func ProofDLK(ep *elliptic.CurveParams, pointA Point, x *big.Int) (ZKproof, Point) {
	w := randBigInt(ep)
	wBytes := w.Bytes()

	var pointH Point
	pointH.x, pointH.y = ep.ScalarMult(ep.Gx, ep.Gy, wBytes)

	e := sha256.New()
	e.Write(ep.Gx.Bytes())
	e.Write(ep.Gy.Bytes())

	e.Write(pointA.x.Bytes())
	e.Write(pointA.y.Bytes())

	e.Write(pointH.x.Bytes())
	e.Write(pointH.y.Bytes())

	e1 := e.Sum(nil)

	var dlk ZKproof
	dlk.E = new(big.Int).SetBytes(e1)
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

	e := sha256.New()
	e.Write(ep.Gx.Bytes())
	e.Write(ep.Gy.Bytes())

	e.Write(pointA.x.Bytes())
	e.Write(pointA.y.Bytes())

	e.Write(pointH.x.Bytes())
	e.Write(pointH.y.Bytes())

	//fixme: we need more meaningful names instead of temp, pointTemp1, pointTemp2
	e1 := e.Sum(nil)
	temp := new(big.Int).SetBytes(e1)

	return temp.Cmp(dl.E) == 0
}

func ProofDLE(ep *elliptic.CurveParams, pointY, pointT, pointZ Point, x *big.Int) (ZKproof, Point, Point) {
	w := randBigInt(ep)
	wBytes := w.Bytes()

	var pointA1, pointA2 Point
	var mul *big.Int
	pointA1.x, pointA1.y = ep.ScalarMult(pointT.x, pointT.y, wBytes)

	pointA2.x, pointA2.y = ep.ScalarMult(ep.Gx, ep.Gy, wBytes)

	e := sha256.New()
	e.Write(pointY.x.Bytes())
	e.Write(pointY.y.Bytes())

	e.Write(pointZ.x.Bytes())
	e.Write(pointZ.y.Bytes())

	e.Write(pointA1.x.Bytes())
	e.Write(pointA1.y.Bytes())

	e.Write(pointA2.x.Bytes())
	e.Write(pointA2.y.Bytes())

	e1 := e.Sum(nil)

	var dle ZKproof
	dle.E = new(big.Int).SetBytes(e1)
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

	e := sha256.New()

	e.Write(pointY.x.Bytes())
	e.Write(pointY.y.Bytes())

	e.Write(pointZ.x.Bytes())
	e.Write(pointZ.y.Bytes())

	e.Write(pointA1.x.Bytes())
	e.Write(pointA1.y.Bytes())

	e.Write(pointA2.x.Bytes())
	e.Write(pointA2.y.Bytes())

	e1 := e.Sum(nil)
	temp := new(big.Int).SetBytes(e1)

	return temp.Cmp(dl.E) == 0
}

//DKG is n-n distributed key generation protocol
func DKG(curve elliptic.Curve, n int) []Participant {
	parties := make([]Participant, n)
	for i := range parties {
		//each participant generates partial key
		parties[i].GenerateKeyPair(curve)
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
