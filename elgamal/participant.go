package elgamal

import "crypto/elliptic"

//Participant of the random generation process
type Participant struct {
	PartialKey KeyPair
	CommonKey  Point
	ID         int
}

//NewParticipant fill pair of secret and public key into the participant p.
func NewParticipant(curve elliptic.Curve) Participant {
	ep := curve.Params()
	//secret key
	x := randBigInt(ep)
	//public key

	qx, qy := ep.ScalarMult(ep.Gx, ep.Gy, x.Bytes())
	keyPair := KeyPair{x, Point{qx, qy}}

	return Participant{PartialKey: keyPair}
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

//PartialDecrypt returns share of the decryption key for the particular ciphertext C
func (p Participant) PartialDecrypt(curve elliptic.Curve, ct Ciphertext) (point Point) {
	point.x, point.y = curve.ScalarMult(ct.pointA.x, ct.pointA.y, p.PartialKey.SecretKey.Bytes())
	return
}