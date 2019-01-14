package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

//Point represent points on the elliptic curve P = (x, y)
//Open messages are elliptic curve's points.
type Point struct {
	x *big.Int
	y *big.Int
}

//Ciphertext is usual ElGamal ciphertext C = (A, B)
//Here A, B - the elliptic curve's points.
type Ciphertext struct {
	A Point
	B Point
}
type ZKproof struct {
	Q Point
	e *big.Int
	z *big.Int
}

//KeyPair contains secret and public keys for ElGamal cryptosystem
type KeyPair struct {
	secretKey *big.Int
	publicKey Point
}

//Participant of the random generation process
type Participant struct {
	partialKey KeyPair
	commonKey  KeyPair
	id         int
}

// creating big random value of type big int
func randBigInt(E elliptic.Curve) *big.Int {
	max := E.Params().P
	y, err := rand.Int(rand.Reader, max)
	if err != nil {
	}
	return y
}

//Generate random message (point) on the elliptic curve E
func generateMessage(Ep *elliptic.CurveParams) Point {
	y := randBigInt(Ep)
	byteY := y.Bytes()
	Mx, My := Ep.ScalarMult(Ep.Gx, Ep.Gy, byteY)
	return Point{Mx, My}
}

//generate new secret and public keys
func (p *Participant) generateKeyPair(E elliptic.Curve) KeyPair {
	var Ep = E.Params()
	//secret key
	x := randBigInt(Ep)
	byteX := x.Bytes()
	//public key
	Qx, Qy := Ep.ScalarMult(Ep.Gx, Ep.Gy, byteX)
	var keyPair = KeyPair{x, Point{Qx, Qy}}
	p.partialKey = keyPair
	return keyPair
}

//encrypt message
func encrypt(Ep *elliptic.CurveParams, M Point, Q Point) (Ciphertext, ZKproof) {
	var r *big.Int
	r = randBigInt(Ep)
	byteR := r.Bytes()
	var Ax, Ay = Ep.ScalarMult(Ep.Gx, Ep.Gy, byteR)
	var Bx, By = Ep.ScalarMult(Q.x, Q.y, byteR)
	Bx, By = Ep.Add(M.x, M.y, Bx, By)
	A := Point{Ax, Ay}
	B := Point{Bx, By}
	var C = Ciphertext{A, B}
	var dlk = DLK(Ep, A, r)
	return C, dlk
}

func aggregateMessage(Ep *elliptic.CurveParams, C [1]Ciphertext) Ciphertext {
	var genC Ciphertext
	genC.A.x, genC.A.y = C[0].A.x, C[0].A.y
	genC.B.x, genC.B.y = C[0].B.x, C[0].B.y
	//for i := 1; i < 10; i++ {
	//	GenC.Ax, GenC.Ay = Ep.Add(GenC.Ax, GenC.Ay, C[i].Ax, C[i].Ay)
	//	GenC.Bx, GenC.By = Ep.Add(GenC.Bx, GenC.By, C[i].Bx, C[i].By)
	//}
	return genC
}

func decrypt(Ep *elliptic.CurveParams, C Ciphertext, x *big.Int) Point {
	var Mx, My, tempx, tempy *big.Int
	Bytex := x.Bytes()
	tempx, tempy = Ep.ScalarMult(C.A.x, C.A.y, Bytex)
	tempy = tempy.Neg(tempy)
	Mx, My = Ep.Add(C.B.x, C.B.y, tempx, tempy)
	var M = Point{Mx, My}
	return M
}

func (p1 Point) add(E elliptic.Curve, p2 Point) Point {
	x, y := E.Params().Add(p1.x, p1.y, p2.x, p2.y)
	return Point{x, y}
}

func (p1 Point) neg() Point {
	var y = p1.y.Neg(p1.y)
	return Point{p1.x, y}
}

func (firstKey KeyPair) publicKeyAdd(E elliptic.Curve, secondKey KeyPair) KeyPair {
	result := firstKey.publicKey.add(E, secondKey.publicKey)
	return KeyPair{firstKey.secretKey, result}
}

func (p Participant) partialDecrypt(E elliptic.Curve, C Ciphertext) Point {
	var x, y = E.ScalarMult(C.A.x, C.A.y, p.partialKey.secretKey.Bytes())
	return Point{x, y}
}

func DLK(Ep *elliptic.CurveParams, A Point, x *big.Int) ZKproof {
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
	dlk.e = new(big.Int).SetBytes(e1)
	mul = new(big.Int).Mul(x, dlk.e)
	dlk.z = new(big.Int).Sub(w, mul)
	dlk.Q = A
	return dlk
}
func checkDLK(Ep *elliptic.CurveParams, dl ZKproof) bool {
	var H1, temp1, temp2 Point
	var check = false
	negz := new(big.Int).Mod(dl.z, Ep.N)
	temp1.x, temp1.y = Ep.ScalarMult(Ep.Gx, Ep.Gy, negz.Bytes())
	temp2.x, temp2.y = Ep.ScalarMult(dl.Q.x, dl.Q.y, dl.e.Bytes())
	H1.x, H1.y = Ep.Add(temp1.x, temp1.y, temp2.x, temp2.y)
	e := sha256.New()
	e.Write(Ep.Gx.Bytes())
	e.Write(Ep.Gy.Bytes())
	e.Write(dl.Q.x.Bytes())
	e.Write(dl.Q.y.Bytes())
	e.Write(H1.x.Bytes())
	e.Write(H1.y.Bytes())
	e2 := e.Sum(nil)
	e1 := e2[:]
	temp := new(big.Int).SetBytes(e1)
	if temp.Cmp(dl.e) == 0 {
		check = true
	}
	return check
}

func main() {
	//number of parties
	const n = 3
	//
	var parties [n]Participant
	// creating elliptic curve
	E := elliptic.P256()
	Ep := E.Params()
	// generating key
	var partialKeys [n]KeyPair
	for i := 0; i < n; i++ {
		//each participant generates partial key
		partialKeys[i] = parties[i].generateKeyPair(E)
		//then he publishes partialKey.publicKey and everyone knows the public key of i-th participant
	}
	//generating common public key as sum of all partial keys
	commonKey := KeyPair{publicKey: parties[0].partialKey.publicKey}
	for i := 1; i < n; i++ {
		commonKey = commonKey.publicKeyAdd(E, parties[i].partialKey)
	}
	//each participant saves new common key
	//for _, party := range parties {
	for i := 0; i < n; i++ {
		parties[i].commonKey = commonKey
	}
	//Encrypt some message with the common key
	var M Point
	M = generateMessage(Ep)
	//fmt.Println(M.x, M.y)
	//fmt.Println(parties[0].commonKey.publicKey)
	var C, Cdlk = encrypt(Ep, M, parties[0].commonKey.publicKey)
	fmt.Println(checkDLK(Ep, Cdlk))
	/*var C [n]Ciphertext
	for i := 0; i < n; i++ {
		M = generateMessage(Ep)
		fmt.Println(M.x, M.y)
		C[i] = encrypt(Ep, M, parties[0].commonKey.publicKey)
	}
	//3. calculate `C = (A, B)`
	//var genC Ciphertext
	//genC = aggregateMessage(Ep, C)
	//5. Decrypt M*/
	//each participant publishes partial decrypt of the ciphertext
	var decryptParts [n]Point
	for i := range parties {
		decryptParts[i] = parties[i].partialDecrypt(E, C)
	}
	//aggregating all parts
	decryptKey := decryptParts[0]
	for i := 1; i < n; i++ {
		decryptKey = decryptKey.add(E, decryptParts[i])
	}
	newM := C.B.add(E, decryptKey.neg())
	fmt.Println(newM.x, newM.y)

}
