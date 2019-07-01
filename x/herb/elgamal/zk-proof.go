package elgamal

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof"
	"go.dedis.ch/kyber/v3/proof/dleq"
)

func DLK(group proof.Suite, B kyber.Point, x kyber.Scalar, X kyber.Point) (DLKproof []byte, err error) {
	predDLK := proof.Rep("X", "x", "B")
	sval := map[string]kyber.Scalar{"x": x}
	pval := map[string]kyber.Point{"B": B, "X": X}
	prover := predDLK.Prover(group, sval, pval, nil)
	DLKproof, err = proof.HashProve(group, "DLK", prover)
	return
}
func RK(group proof.Suite, B1 kyber.Point, x1 kyber.Scalar, B2 kyber.Point, x2 kyber.Scalar, X kyber.Point) (RKproof []byte, err error) {
	predRK := proof.Rep("X", "x1", "B1", "x2", "B2")
	sval := map[string]kyber.Scalar{"x1": x1, "x2": x2}
	pval := map[string]kyber.Point{"B1": B1, "B2": B2, "X": X}
	prover := predRK.Prover(group, sval, pval, nil)
	RKproof, err = proof.HashProve(group, "RK", prover)
	return
}
func DLE(group proof.Suite, B kyber.Point, X kyber.Point, x kyber.Scalar) (DLEproof *dleq.Proof, xB kyber.Point, xX kyber.Point, err error) {
	DLEproof, xB, xX, err = dleq.NewDLEQProof(group, B, X, x)
	return
}

func DLKVerify(group proof.Suite, X kyber.Point, B kyber.Point, DLKproof []byte) (err error) {
	predDLK := proof.Rep("X", "x", "B")
	pval := map[string]kyber.Point{"B": B, "X": X}
	verifier := predDLK.Verifier(group, pval)
	err = proof.HashVerify(group, "DLK", verifier, DLKproof)
	return
}

func RKVerify(group proof.Suite, X kyber.Point, B1 kyber.Point, B2 kyber.Point, RKproof []byte) (err error) {
	predRK := proof.Rep("X", "x1", "B1", "x2", "B2")
	pval := map[string]kyber.Point{"B1": B1, "B2": B2, "X": X}
	verifier := predRK.Verifier(group, pval)
	err = proof.HashVerify(group, "RK", verifier, RKproof)
	return
}

func DLEVerify(group proof.Suite, DLEproof *dleq.Proof, B kyber.Point, X kyber.Point, xB kyber.Point, xX kyber.Point) (err error) {
	err = DLEproof.Verify(group, B, X, xB, xX)
	return
}
