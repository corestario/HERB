package elgamal

import "crypto/elliptic"

//Ciphertext is usual ElGamal ciphertext C = (a, b)
//Here a, b - the elliptic curve's points
type Ciphertext struct {
	pointA Point
	pointB Point
}

//Decrypt takes decrypt parts (shares) from all participants and decrypt the ciphertext C
func (ct Ciphertext) Decrypt(curve elliptic.Curve, shares []Point) Point {
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

//IsValid return true if both part of the ciphertext C on the curve E.
func (ct Ciphertext) IsValid(curve elliptic.Curve) bool {
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
