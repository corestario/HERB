package elgamal

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

//Point represent points on the elliptic curve P = (x, y)
//Open messages are elliptic curve's points.
type Point struct {
	x *big.Int
	y *big.Int
}

//Ciphertext is usual ElGamal ciphertext C = (A, B)
//Here A, B - the elliptic curve's points
type Ciphertext struct {
	A Point
	B Point
}

//ZKproof represent proof of discrete logarithm knowledge (DLK) or
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

//randBigInt creates big random value in the Fp - curve's field
func randBigInt(E elliptic.Curve) *big.Int {
	max := E.Params().P
	y, err := rand.Int(rand.Reader, max)
	if err != nil {
	}
	return y
}

//GeneratePoint allows to generate random point on the elliptic curve E
func GeneratePoint(E elliptic.Curve) Point {
	Ep := E.Params()
	y := randBigInt(Ep)
	Mx, My := Ep.ScalarMult(Ep.Gx, Ep.Gy, y.Bytes())
	return Point{Mx, My}
}

//GenerateKeyPair return pair of secret and public key for the participant p.
func (p *Participant) GenerateKeyPair(E elliptic.Curve) {
	Ep := E.Params()
	//secret key
	x := randBigInt(Ep)
	//public key
	Qx, Qy := Ep.ScalarMult(Ep.Gx, Ep.Gy, x.Bytes())
	keyPair := KeyPair{x, Point{Qx, Qy}}
	p.PartialKey = keyPair
}

//Encrypt return encrypted message M and proof of t
func (p *Participant) Encrypt(E elliptic.Curve, M Point) Ciphertext {
	Ep := E.Params()
	var r *big.Int
	r = randBigInt(Ep)
	var A, B Point
	//A = rG
	A.x, A.y = Ep.ScalarMult(Ep.Gx, Ep.Gy, r.Bytes())
	//B = rQ + M
	B = p.CommonKey.ScalarMult(Ep, r)
	B = B.Add(Ep, M)
	var C = Ciphertext{A, B}
	//var dlk, A1 = ProofDLK(Ep, A, r)
	return C
}

//Decrypt the ciphertext C with the key x
func decrypt(E elliptic.Curve, C Ciphertext, x *big.Int) Point {
	temp := C.A.ScalarMult(E, x)
	temp.y = temp.y.Neg(temp.y)
	//M = B - xA
	M := C.B.Add(E, temp)
	return M
}

//IsValidCiphertext return true if both part of the ciphertext C on the curve E.
func IsValidCiphertext(C Ciphertext, E elliptic.Curve) bool {
	statement1 := E.IsOnCurve(C.A.x, C.A.y)
	statement2 := E.IsOnCurve(C.B.x, C.B.y)
	return statement1 && statement2
}

//AggregateCiphertext takes the set of ciphertextes parts:
//parts[0] = (A0, B0), ..., parts[n] = (An, Bn)
//and returns aggregated ciphertext C = (A1 + A2 + ... + An, B1 + B2 + ... + Bn)
func AggregateCiphertext(E elliptic.Curve, parts []Ciphertext) Ciphertext {
	var C Ciphertext
	for i := range parts {
		if i == 0 {
			C.A = parts[0].A
			C.B = parts[0].B
		} else {
			C.A = C.A.Add(E, parts[0].A)
			C.B = C.B.Add(E, parts[0].B)
		}
	}
	return C
}

func (p1 Point) Add(E elliptic.Curve, p2 Point) Point {
	x, y := E.Params().Add(p1.x, p1.y, p2.x, p2.y)
	return Point{x, y}
}

func (p1 Point) Neg() Point {
	var y = p1.y.Neg(p1.y)
	return Point{p1.x, y}
}

func (p1 Point) ScalarMult(E elliptic.Curve, t *big.Int) Point {
	x, y := E.ScalarMult(p1.x, p1.y, t.Bytes())
	return Point{x, y}
}

func CurveGenerator(ec elliptic.Curve) Point {
	Ep := ec.Params()
	return Point{Ep.Gx, Ep.Gy}
}

func (firstKey KeyPair) PublicKeyAdd(E elliptic.Curve, secondKey KeyPair) KeyPair {
	result := firstKey.PublicKey.Add(E, secondKey.PublicKey)
	return KeyPair{firstKey.SecretKey, result}
}

func (p Participant) PartialDecrypt(E elliptic.Curve, C Ciphertext) Point {
	var x, y = E.ScalarMult(C.A.x, C.A.y, p.PartialKey.SecretKey.Bytes())
	return Point{x, y}
}

func ProofDLK(Ep *elliptic.CurveParams, A Point, x *big.Int) (ZKproof, Point) {
	var dlk ZKproof
	w := randBigInt(Ep)
	Bytew := w.Bytes()
	var H Point
	var mul *big.Int
	H.x, H.y = Ep.ScalarMult(Ep.Gx, Ep.Gy, Bytew)
	e := sha256.New()
	e.Write(Ep.Gx.Bytes())
	e.Write(Ep.Gy.Bytes())
	e.Write(A.x.Bytes())
	e.Write(A.y.Bytes())
	e.Write(H.x.Bytes())
	e.Write(H.y.Bytes())
	e2 := e.Sum(nil)
	e1 := e2[:]
	dlk.E = new(big.Int).SetBytes(e1)
	mul = new(big.Int).Mul(x, dlk.E)
	dlk.Z = new(big.Int).Sub(w, mul)
	return dlk, A
}
func VerifyDLK(Ep *elliptic.CurveParams, dl ZKproof, A Point) bool {
	var H1, temp1, temp2 Point
	var check = false
	negz := new(big.Int).Mod(dl.Z, Ep.N)
	temp1.x, temp1.y = Ep.ScalarMult(Ep.Gx, Ep.Gy, negz.Bytes())
	temp2.x, temp2.y = Ep.ScalarMult(A.x, A.y, dl.E.Bytes())
	H1.x, H1.y = Ep.Add(temp1.x, temp1.y, temp2.x, temp2.y)
	e := sha256.New()
	e.Write(Ep.Gx.Bytes())
	e.Write(Ep.Gy.Bytes())
	e.Write(A.x.Bytes())
	e.Write(A.y.Bytes())
	e.Write(H1.x.Bytes())
	e.Write(H1.y.Bytes())
	e2 := e.Sum(nil)
	e1 := e2[:]
	temp := new(big.Int).SetBytes(e1)
	if temp.Cmp(dl.E) == 0 {
		check = true
	}
	return check
}
func ProofDLE(Ep *elliptic.CurveParams, Y, T, Z Point, x *big.Int) (ZKproof, Point, Point) {
	var dle ZKproof
	w := randBigInt(Ep)
	Bytew := w.Bytes()
	var A1, A2 Point
	var mul *big.Int
	A1.x, A1.y = Ep.ScalarMult(T.x, T.y, Bytew)
	A2.x, A2.y = Ep.ScalarMult(Ep.Gx, Ep.Gy, Bytew)
	e := sha256.New()
	e.Write(Y.x.Bytes())
	e.Write(Y.y.Bytes())
	e.Write(Z.x.Bytes())
	e.Write(Z.y.Bytes())
	e.Write(A1.x.Bytes())
	e.Write(A1.y.Bytes())
	e.Write(A2.x.Bytes())
	e.Write(A2.y.Bytes())
	e2 := e.Sum(nil)
	e1 := e2[:]
	dle.E = new(big.Int).SetBytes(e1)
	mul = new(big.Int).Mul(x, dle.E)
	dle.Z = new(big.Int).Sub(w, mul)
	return dle, Y, Z
}
func VerifyDLE(Ep *elliptic.CurveParams, dl ZKproof, Y, T, Z Point) bool {
	var A1, A2, temp1, temp2 Point
	var check = false
	negz := new(big.Int).Mod(dl.Z, Ep.N)
	temp1.x, temp1.y = Ep.ScalarMult(T.x, T.y, negz.Bytes())
	temp2.x, temp2.y = Ep.ScalarMult(Y.x, Y.y, dl.E.Bytes())
	A1.x, A1.y = Ep.Add(temp1.x, temp1.y, temp2.x, temp2.y)
	temp1.x, temp1.y = Ep.ScalarMult(Ep.Gx, Ep.Gy, negz.Bytes())
	temp2.x, temp2.y = Ep.ScalarMult(Z.x, Z.y, dl.E.Bytes())
	A2.x, A2.y = Ep.Add(temp1.x, temp1.y, temp2.x, temp2.y)
	e := sha256.New()
	e.Write(Y.x.Bytes())
	e.Write(Y.y.Bytes())
	e.Write(Z.x.Bytes())
	e.Write(Z.y.Bytes())
	e.Write(A1.x.Bytes())
	e.Write(A1.y.Bytes())
	e.Write(A2.x.Bytes())
	e.Write(A2.y.Bytes())
	e2 := e.Sum(nil)
	e1 := e2[:]
	temp := new(big.Int).SetBytes(e1)
	if temp.Cmp(dl.E) == 0 {
		check = true
	}
	return check
}

//DKG is n-n distributed key generation protocol
func DKG(E elliptic.Curve, n int) []Participant {
	parties := make([]Participant, n)
	for i := 0; i < n; i++ {
		//each participant generates partial key
		parties[i].GenerateKeyPair(E)
		//then he publishes partialKey.publicKey and everyone knows the public key of i-th participant
	}
	//generating common public key as sum of all partial keys
	commonKey := Point{parties[0].PartialKey.PublicKey.x, parties[0].PartialKey.PublicKey.y}
	for i := 1; i < n; i++ {
		commonKey = commonKey.Add(E, parties[i].PartialKey.PublicKey)
	}
	//each participant saves new common key
	for i := 0; i < n; i++ {
		parties[i].CommonKey = commonKey
	}

	return parties
}
