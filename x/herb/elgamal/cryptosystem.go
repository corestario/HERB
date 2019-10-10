package elgamal

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof"
	"go.dedis.ch/kyber/v3/proof/dleq"
	"go.dedis.ch/kyber/v3/util/random"
)

// RandomCiphertext creates an elgamal ciphertext with a random plaintext
func RandomCiphertext(group proof.Suite, commonKey kyber.Point) (ct Ciphertext, CEproof []byte, err error) {
	y := group.Scalar().Pick(random.New())
	M := group.Point().Mul(y, nil)
	r := group.Scalar().Pick(random.New())
	S := group.Point().Mul(r, commonKey)
	A := group.Point().Mul(r, nil)
	B := S.Add(group.Point().Mul(r, commonKey), M)
	ct = Ciphertext{A, B}
	CEproof, err = CE(group, group.Point().Base(), commonKey, A, B, r, y)
	if err != nil {
		return
	}
	return
}

// create decryption shares and proof
func CreateDecShare(group proof.Suite, C Ciphertext, partKey kyber.Scalar) (decShare kyber.Point, DLEQproof *dleq.Proof, err error) {
	decShare = group.Point().Mul(partKey, C.PointA)
	DLEQproof, _, _, err = DLEQ(group, group.Point().Base(), C.PointA, partKey)
	if err != nil {
		return nil, nil, err
	}
	return
}
