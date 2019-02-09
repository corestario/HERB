package elgamal

import (
	"crypto/elliptic"

	"github.com/dgamingfoundation/HERB/point"
	"github.com/dgamingfoundation/HERB/rand"
)

//Participant of the random generation process
type Participant struct {
	PartialKey KeyPair
	CommonKey  point.Point
	ID         int
}

//NewParticipant fill pair of secret and public key into the participant p.
func NewParticipant(curve elliptic.Curve, id int) Participant {
	ep := curve.Params()
	//secret key
	x := rand.RandEllipticKey(ep)
	//public key

	qx, qy := ep.ScalarMult(ep.Gx, ep.Gy, x.Bytes())
	keyPair := KeyPair{x, point.Point{qx, qy}}

	return Participant{PartialKey: keyPair, ID: id}
}

//Encrypt return encrypted message M and proof of t
func (p Participant) Encrypt(curve elliptic.Curve, pointM point.Point) Ciphertext {
	ep := curve.Params()
	r := rand.RandEllipticKey(ep)

	var pointA, pointB point.Point
	//pointA = rG
	pointA.Set(ep.ScalarMult(ep.Gx, ep.Gy, r.Bytes()))

	//pointB = rQ + M
	pointB = p.CommonKey.ScalarMult(ep, r).Add(ep, pointM)

	//var dlk, A1 = ProofDLK(Ep, pointA, r)
	return Ciphertext{pointA, pointB}
}

//PartialDecrypt returns share of the decryption key for the particular ciphertext C
func (p Participant) PartialDecrypt(curve elliptic.Curve, ct Ciphertext) (point point.Point) {
	point.Set(curve.ScalarMult(ct.pointA.GetX(), ct.pointA.GetY(), p.PartialKey.SecretKey.Bytes()))
	return
}

//IsEqual compares two participants and returns true if they have equal ID, common key and public key
func (p Participant) IsEqual(p1 Participant) bool {
	return p.CommonKey.IsEqual(p1.CommonKey) && p.ID == p1.ID && p.PartialKey.IsEqual(p1.PartialKey)
}
