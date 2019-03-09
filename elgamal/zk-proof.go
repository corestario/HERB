package elgamal

import (
	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/proof"
)

func DLK(group proof.Suite, B kyber.Point, x kyber.Scalar, X kyber.Point) (DLKproof []byte, predDLK proof.Predicate, err error) {
	predDLK = proof.Rep("X", "x", "B")
	sval := map[string]kyber.Scalar{"x": x}
	pval := map[string]kyber.Point{"B": B, "X": X}
	prover := predDLK.Prover(group, sval, pval, nil)
	DLKproof, err = proof.HashProve(group, "DLK", prover)
	return
}
func DLKVerify(group proof.Suite, X kyber.Point, B kyber.Point, predDLK proof.Predicate, DLKproof []byte) (err error) {
	pval := map[string]kyber.Point{"B": B, "X": X}
	verifier := predDLK.Verifier(group, pval)
	err = proof.HashVerify(group, "DLK", verifier, DLKproof)
	return
}
