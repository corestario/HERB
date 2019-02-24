package elgamal

import (
	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/share"
)

//Ciphertext is usual ElGamal ciphertext C = (a, b)
//Here a, b - the elliptic curve's points
type Ciphertext struct {
	PointA kyber.Point
	PointB kyber.Point
}

//IdentityCiphertext creates ciphertext which is neutral with respect to plaintext group operation (after ciphertext aggregation operation)
//func IdentityCiphertext(curve elliptic.Curve) Ciphertext {
//	return Ciphertext{point.PointAtInfinity(curve), point.PointAtInfinity(curve)}
//}

//Decrypt takes decrypt parts (shares) from all participants and decrypt the ciphertext C
func Decrypt(group kyber.Group, C Ciphertext, parts []kyber.Point, t, n int) kyber.Point {
	pubShares := make([]*share.PubShare, t)
	for i := 0; i < t; i++ {
		pubShares[i] = &share.PubShare{i, parts[i]}
	}
	D, _ := share.RecoverCommit(group, pubShares, t, n)
	M := group.Point().Sub(C.PointB, D)
	return M
}

//IsValid return true if both part of the ciphertext C on the curve E.
//func (ct Ciphertext) IsValid(curve elliptic.Curve) bool {
//	statement1 := curve.IsOnCurve(ct.pointA.GetX(), ct.pointA.GetY())
//	statement2 := curve.IsOnCurve(ct.pointB.GetX(), ct.pointB.GetY())
//	return statement1 && statement2
//}

//Equal compares two ciphertexts and returns true if ct = ct1
//func (ct Ciphertext) Equal(ct1 Ciphertext) bool {
//	return ct.pointA.Equal(ct1.pointA) && ct.pointB.Equal(ct1.pointB)
//}

//AggregateCiphertext takes the set of ciphertextes parts:
//parts[0] = (A0, B0), ..., parts[n] = (An, Bn)
//and returns aggregated ciphertext C = (A1 + A2 + ... + An, B1 + B2 + ... + Bn)
func AggregateCiphertext(group kyber.Group, parts []Ciphertext) Ciphertext {
	//if len(parts) == 0 {
	//	return IdentityCiphertext(curve)
	//}
	ct := Ciphertext{parts[0].PointA, parts[0].PointB}
	for i := 1; i < len(parts); i++ {
		ct.PointA = group.Point().Add(ct.PointA, parts[i].PointA)
		ct.PointB = group.Point().Add(ct.PointB, parts[i].PointB)
	}

	return ct
}
