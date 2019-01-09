package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

//Ciphertext is usual ElGamal ciphertext C = (A, B)
//Here A, B - the elliptic curve's points.
type Ciphertext struct {
	A Point
	B Point
}

//Point represent points on the elliptic curve P = (x, y)
//Open messages are elliptic curve's points.
type Point struct {
	x *big.Int
	y *big.Int
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

//encrypt message
func encrypt(Ep *elliptic.CurveParams, M Point, Q Point) Ciphertext {
	var r *big.Int
	r = randBigInt(Ep)
	byteR := r.Bytes()
	var Ax, Ay = Ep.ScalarMult(Ep.Gx, Ep.Gy, byteR)
	var Bx, By = Ep.ScalarMult(Q.x, Q.y, byteR)
	Bx, By = Ep.Add(M.x, M.y, Bx, By)
	var C = Ciphertext{Point{Ax, Ay}, Point{Bx, By}}
	return C
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

func main() {
	// creating elliptic curve
	E := elliptic.P256()
	Ep := E.Params()
	//secret key
	x := randBigInt(Ep)
	Bytex := x.Bytes()
	//public key
	Qx, Qy := Ep.ScalarMult(Ep.Gx, Ep.Gy, Bytex)
	var Q = Point{Qx, Qy}
	//1.
	var M Point
	var C [1]Ciphertext
	for i := 0; i < 1; i++ {
		M = generateMessage(Ep)
		fmt.Println(M.x, M.y)
		C[i] = encrypt(Ep, M, Q)
	}
	//3. calculate `C = (A, B)`
	var genC Ciphertext
	genC = aggregateMessage(Ep, C)
	//5. Decrypt M
	var newM Point
	newM = decrypt(Ep, genC, x)
	fmt.Println(newM.x, newM.y)

}
