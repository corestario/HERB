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
	a Point
	b Point
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
func (p *Point) X() big.Int {
	return *p.x
}

//Y coordinate of the point p
func (p *Point) Y() big.Int {
	return *p.y
}

func (p Point) add(e elliptic.Curve, p2 Point) Point {
	x, y := e.Params().Add(p.x, p.y, p2.x, p2.y)
	return Point{x, y}
}

func (p Point) neg() Point {
	var y = p.y.Neg(p.y)
	return Point{p.x, y}
}

func (p Point) scalarMult(e elliptic.Curve, t *big.Int) Point {
	x, y := e.ScalarMult(p.x, p.y, t.Bytes())
	return Point{x, y}
}

///////
//
///////

//randBigInt creates big random value in the Fp - curve's field
func randBigInt(e elliptic.Curve) *big.Int {
	max := e.Params().P
	y, _ := rand.Int(rand.Reader, max)
	//fixme we need to handle this err value somehow
	return y
}

//GeneratePoint allows to generate random point on the elliptic curve E
func GeneratePoint(e elliptic.Curve) Point {
	ep := e.Params()
	y := randBigInt(ep)
	mx, my := ep.ScalarMult(ep.Gx, ep.Gy, y.Bytes())
	return Point{mx, my}
}

//GenerateKeyPair return pair of secret and public key for the participant p.
func (p *Participant) GenerateKeyPair(e elliptic.Curve) {
	ep := e.Params()
	//secret key
	x := randBigInt(ep)
	//public key
	qx, qy := ep.ScalarMult(ep.Gx, ep.Gy, x.Bytes())
	keyPair := KeyPair{x, Point{qx, qy}}
	p.PartialKey = keyPair
}

//Encrypt return encrypted message M and proof of t
func (p *Participant) Encrypt(e elliptic.Curve, m Point) Ciphertext {
	ep := e.Params()
	r := randBigInt(ep)

	var a, b Point
	//a = rG
	a.x, a.y = ep.ScalarMult(ep.Gx, ep.Gy, r.Bytes())

	//b = rQ + M
	b = p.CommonKey.scalarMult(ep, r).add(ep, m)

	//var dlk, A1 = ProofDLK(Ep, a, r)
	return Ciphertext{a, b}
}

//Decrypt the ciphertext C with the key x
//Currently not in use
func decrypt(e elliptic.Curve, ct Ciphertext, x *big.Int) Point {
	temp := ct.a.scalarMult(e, x)
	temp.y = temp.y.Neg(temp.y)
	//M = b - xA
	M := ct.b.add(e, temp)
	return M
}

//DecryptFromShares takes decrypt parts (shares) from all participants and decrypt the ciphertext C
func DecryptFromShares(e elliptic.Curve, shares []Point, ct Ciphertext) Point {
	//aggregating all parts
	decryptKey := shares[0]
	for i := 1; i < len(shares); i++ {
		decryptKey = decryptKey.add(e, shares[i])
	}
	M := ct.b.add(e, decryptKey.neg())
	return M
}

//IsValidCiphertext return true if both part of the ciphertext C on the curve E.
func IsValidCiphertext(ct Ciphertext, e elliptic.Curve) bool {
	statement1 := e.IsOnCurve(ct.a.x, ct.a.y)
	statement2 := e.IsOnCurve(ct.b.x, ct.b.y)
	return statement1 && statement2
}

//AggregateCiphertext takes the set of ciphertextes parts:
//parts[0] = (A0, B0), ..., parts[n] = (An, Bn)
//and returns aggregated ciphertext C = (A1 + A2 + ... + An, B1 + B2 + ... + Bn)
func AggregateCiphertext(e elliptic.Curve, parts []Ciphertext) Ciphertext {
	if len(parts) == 0 {
		//fixme: is it a correct return value?
		return Ciphertext{}
	}

	ct := Ciphertext{parts[0].a, parts[0].b}
	for i := 1; i < len(parts); i++ {
		//fixme: please re-check me. it was `parts[0]`
		ct.a = ct.a.add(e, parts[i].a)
		ct.b = ct.b.add(e, parts[i].b)
	}

	return ct
}

//PublicKeyRecover recovers common public key from partial keys of participants
func PublicKeyRecover(e elliptic.Curve, keys []Point) Point {
	if len(keys) == 0 {
		//fixme: is it a correct return value?
		return Point{}
	}

	result := keys[0]
	for i := 1; i < len(keys); i++ {
		result = result.add(e, keys[i])
	}

	return result
}

//PartialDecrypt returns share of the decryption key for the particular ciphertext C
func (p Participant) PartialDecrypt(e elliptic.Curve, ct Ciphertext) Point {
	var x, y = e.ScalarMult(ct.a.x, ct.a.y, p.PartialKey.SecretKey.Bytes())
	return Point{x, y}
}

//Proofs currently not in use

//ProofDLK creates discrete logarithm knowledge proof for a = xG
func ProofDLK(ep *elliptic.CurveParams, a Point, x *big.Int) (ZKproof, Point) {
	w := randBigInt(ep)
	wBytes := w.Bytes()

	var h Point
	h.x, h.y = ep.ScalarMult(ep.Gx, ep.Gy, wBytes)

	e := sha256.New()
	e.Write(ep.Gx.Bytes())
	e.Write(ep.Gy.Bytes())

	e.Write(a.x.Bytes())
	e.Write(a.y.Bytes())

	e.Write(h.x.Bytes())
	e.Write(h.y.Bytes())

	e2 := e.Sum(nil)

	var dlk ZKproof
	dlk.E = new(big.Int).SetBytes(e2)
	mul := new(big.Int).Mul(x, dlk.E)
	dlk.Z = new(big.Int).Sub(w, mul)

	return dlk, a
}

//VerifyDLK verify discrete logarithm knowledge proof for a = xG
func VerifyDLK(ep *elliptic.CurveParams, dl ZKproof, a Point) bool {
	negZ := new(big.Int).Mod(dl.Z, ep.N)

	var h1, temp1, temp2 Point
	temp1.x, temp1.y = ep.ScalarMult(ep.Gx, ep.Gy, negZ.Bytes())
	temp2.x, temp2.y = ep.ScalarMult(a.x, a.y, dl.E.Bytes())

	h1.x, h1.y = ep.Add(temp1.x, temp1.y, temp2.x, temp2.y)

	e := sha256.New()
	e.Write(ep.Gx.Bytes())
	e.Write(ep.Gy.Bytes())

	e.Write(a.x.Bytes())
	e.Write(a.y.Bytes())

	e.Write(h1.x.Bytes())
	e.Write(h1.y.Bytes())

	//fixme: we need more meaningful names instead of temp, temp1, temp2
	e1 := e.Sum(nil)
	temp := new(big.Int).SetBytes(e1)

	return temp.Cmp(dl.E) == 0
}

func ProofDLE(ep *elliptic.CurveParams, y, t, z Point, x *big.Int) (ZKproof, Point, Point) {
	w := randBigInt(ep)
	wBytes := w.Bytes()

	var a1, a2 Point
	var mul *big.Int
	a1.x, a1.y = ep.ScalarMult(t.x, t.y, wBytes)

	a2.x, a2.y = ep.ScalarMult(ep.Gx, ep.Gy, wBytes)

	e := sha256.New()
	e.Write(y.x.Bytes())
	e.Write(y.y.Bytes())

	e.Write(z.x.Bytes())
	e.Write(z.y.Bytes())

	e.Write(a1.x.Bytes())
	e.Write(a1.y.Bytes())

	e.Write(a2.x.Bytes())
	e.Write(a2.y.Bytes())

	e1 := e.Sum(nil)

	var dle ZKproof
	dle.E = new(big.Int).SetBytes(e1)
	mul = new(big.Int).Mul(x, dle.E)
	dle.Z = new(big.Int).Sub(w, mul)

	return dle, y, z
}
func VerifyDLE(ep *elliptic.CurveParams, dl ZKproof, y, t, z Point) bool {
	var a1, a2, temp1, temp2 Point

	negz := new(big.Int).Mod(dl.Z, ep.N)
	temp1.x, temp1.y = ep.ScalarMult(t.x, t.y, negz.Bytes())
	temp2.x, temp2.y = ep.ScalarMult(y.x, y.y, dl.E.Bytes())

	a1.x, a1.y = ep.Add(temp1.x, temp1.y, temp2.x, temp2.y)

	temp1.x, temp1.y = ep.ScalarMult(ep.Gx, ep.Gy, negz.Bytes())
	temp2.x, temp2.y = ep.ScalarMult(z.x, z.y, dl.E.Bytes())

	a2.x, a2.y = ep.Add(temp1.x, temp1.y, temp2.x, temp2.y)

	e := sha256.New()

	e.Write(y.x.Bytes())
	e.Write(y.y.Bytes())

	e.Write(z.x.Bytes())
	e.Write(z.y.Bytes())

	e.Write(a1.x.Bytes())
	e.Write(a1.y.Bytes())

	e.Write(a2.x.Bytes())
	e.Write(a2.y.Bytes())

	e1 := e.Sum(nil)
	temp := new(big.Int).SetBytes(e1)

	return temp.Cmp(dl.E) == 0
}

//DKG is n-n distributed key generation protocol
func DKG(E elliptic.Curve, n int) []Participant {
	parties := make([]Participant, n)
	for i := range parties {
		//each participant generates partial key
		parties[i].GenerateKeyPair(E)
	}

	//then each party publishes partialKey.publicKey and everyone knows the public key of i-th participant
	partialPublicKeys := make([]Point, n)
	for i := range parties {
		partialPublicKeys[i] = parties[i].PartialKey.PublicKey
	}

	//each participant generates common public key from partial keys
	for i := range parties {
		parties[i].CommonKey = PublicKeyRecover(E, partialPublicKeys)
	}

	return parties
}
