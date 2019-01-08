package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

type message struct {
	Ax *big.Int
	Ay *big.Int
	Bx *big.Int
	By *big.Int
}

func randbigInt(Ep *elliptic.CurveParams) *big.Int {
	// creating big random value of type big int
	max := Ep.P
	y, err := rand.Int(rand.Reader, max)
	if err != nil {
	}
	return y
}

//message M
func generateMessage(Ep *elliptic.CurveParams) (*big.Int, *big.Int) {
	y := randbigInt(Ep)
	ByteY := y.Bytes()
	Mx, My := Ep.ScalarMult(Ep.Gx, Ep.Gy, ByteY)
	return Mx, My
}

//Encrypt message
func Encrypt(Ep *elliptic.CurveParams, Mx *big.Int, My *big.Int, Qx *big.Int, Qy *big.Int) message {
	var r *big.Int
	r = randbigInt(Ep)
	Byter := r.Bytes()
	var Em message
	Em.Ax, Em.Ay = Ep.ScalarMult(Ep.Gx, Ep.Gy, Byter)
	tempx, tempy := Ep.ScalarMult(Qx, Qy, Byter)
	Em.Bx, Em.By = Ep.Add(Mx, My, tempx, tempy)
	return Em
}

func aggregateMessage(Ep *elliptic.CurveParams, C [1]message) message {
	var GenC message
	GenC.Ax, GenC.Ay = C[0].Ax, C[0].Ay
	GenC.Bx, GenC.By = C[0].Bx, C[0].By
	//for i := 1; i < 10; i++ {
	//	GenC.Ax, GenC.Ay = Ep.Add(GenC.Ax, GenC.Ay, C[i].Ax, C[i].Ay)
	//	GenC.Bx, GenC.By = Ep.Add(GenC.Bx, GenC.By, C[i].Bx, C[i].By)
	//}
	return GenC
}

func decrypt(Ep *elliptic.CurveParams, C message, x *big.Int) (*big.Int, *big.Int) {
	var Mx, My, tempx, tempy *big.Int
	Bytex := x.Bytes()
	tempx, tempy = Ep.ScalarMult(C.Ax, C.Ay, Bytex)
	tempy = tempy.Neg(tempy)
	Mx, My = Ep.Add(C.Bx, C.By, tempx, tempy)
	return Mx, My
}

func main() {
	// creating elliptic curve
	E := elliptic.P256()
	Ep := E.Params()
	// base point
	//fmt.Println(Ep.Gx, Ep.Gy)
	// Q point
	x := randbigInt(Ep)
	Bytex := x.Bytes()
	Qx, Qy := Ep.ScalarMult(Ep.Gx, Ep.Gy, Bytex)
	//1.
	var Mx, My *big.Int
	var C [1]message
	for i := 0; i < 1; i++ {
		Mx, My = generateMessage(Ep)
		fmt.Println(Mx, My)
		C[i] = Encrypt(Ep, Mx, My, Qx, Qy)
	}
	//3. calculate `C = (A, B)`
	var GenC message
	GenC = aggregateMessage(Ep, C)
	//5. Decrypt M
	var newMx, newMy *big.Int
	newMx, newMy = decrypt(Ep, GenC, x)
	fmt.Println(newMx, newMy)

}
