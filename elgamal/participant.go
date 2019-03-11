package elgamal

import (
	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/proof"
	"go.dedis.ch/kyber/proof/dleq"
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
func (p Participant) Encrypt(group proof.Suite) (ct Ciphertext, M kyber.Point, DLKproof []byte, RKproof []byte, DLKerr error, RKerr error) {
	y := group.Scalar().Pick(random.New())
	M = group.Point().Mul(y, nil)
	k := group.Scalar().Pick(random.New())
	S := group.Point().Mul(k, p.CommonKey)
	A := group.Point().Mul(k, nil)
	B := S.Add(S, M)
	ct = Ciphertext{A, B}
	DLKproof, DLKerr = DLK(group, group.Point().Base(), k, A)
	RKproof, RKerr = RK(group, group.Point().Base(), y, p.CommonKey, k, B)
	return
}

// Verify DLK-proof and RK-proof for ciphertexts
func (p Participant) VerifyCiphertext(group proof.Suite, DLKproof []byte, ct Ciphertext, RKproof []byte) (DLKerr error, RKerr error) {
	DLKerr = DLKVerify(group, ct.PointA, group.Point().Base(), DLKproof)
	RKerr = RKVerify(group, ct.PointB, group.Point().Base(), p.CommonKey, RKproof)
	return
}

//PartialDecrypt returns share of the decryption key for the particular ciphertext C
func (p Participant) PartialDecrypt(group proof.Suite, C Ciphertext) (
	D kyber.Point, DLEproof *dleq.Proof, H kyber.Point) {
	D = group.Point().Mul(p.PartialKey, C.PointA)
	DLEproof, H, _, _ = DLE(group, group.Point().Base(), C.PointA, p.PartialKey)
	return
}

//verify DLE-prooffor decryption shares
func (p Participant) VerifyDecParts(group proof.Suite, DLEproof *dleq.Proof, ct Ciphertext, D, H kyber.Point) (DLEerr error) {
	DLEerr = DLEVerify(group, DLEproof, group.Point().Base(), ct.PointA, H, D)
	return
}

//Equal compares two participants and returns true if they have equal ID, common key and public key
func (p Participant) Equal(p1 Participant) bool {
	return p.CommonKey.Equal(p1.CommonKey) && p.ID == p1.ID && p.PartialKey.Equal(p1.PartialKey)
}
