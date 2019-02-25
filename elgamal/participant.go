package elgamal

import (
	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/util/random"
)

//Participant of the random generation process
type Participant struct {
	PartialKey kyber.Scalar
	CommonKey  kyber.Point
	ID         int
}

//NewParticipant fill pair of secret and public key into the participant p.
//func NewParticipant(group kyber.Group, id int) Participant {

//}

//Encrypt return encrypted message M and proof of t
func (p Participant) Encrypt(group kyber.Group, message []byte) (
	ct Ciphertext, M kyber.Point) {
	M = group.Point().Embed(message, random.New())
	k := group.Scalar().Pick(random.New())
	S := group.Point().Mul(k, p.CommonKey)
	ct = Ciphertext{group.Point().Mul(k, nil), S.Add(S, M)}
	return
}

//PartialDecrypt returns share of the decryption key for the particular ciphertext C
func (p Participant) PartialDecrypt(group kyber.Group, C Ciphertext) (
	D kyber.Point) {
	D = group.Point().Mul(p.PartialKey, C.PointA)
	return
}

//Equal compares two participants and returns true if they have equal ID, common key and public key
func (p Participant) Equal(p1 Participant) bool {
	return p.CommonKey.Equal(p1.CommonKey) && p.ID == p1.ID && p.PartialKey.Equal(p1.PartialKey)
}
