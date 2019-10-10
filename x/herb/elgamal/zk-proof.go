package elgamal

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof"
	"go.dedis.ch/kyber/v3/proof/dleq"
)

func DLEQ(group proof.Suite, B kyber.Point, X kyber.Point, x kyber.Scalar) (DLEQproof *dleq.Proof, xB kyber.Point, xX kyber.Point, err error) {
	DLEQproof, xB, xX, err = dleq.NewDLEQProof(group, B, X, x)
	return
}
func CE(group proof.Suite, G, Q, A, B kyber.Point, r, x kyber.Scalar) (CEproof []byte, err error) {
	predCE := proof.And(proof.Rep("A", "r", "G"), proof.Rep("B", "r", "Q", "x", "G"))
	sval := map[string]kyber.Scalar{"r": r, "x": x}
	pval := map[string]kyber.Point{"A": A, "G": G, "B": B, "Q": Q}
	prover := predCE.Prover(group, sval, pval, nil)
	CEproof, err = proof.HashProve(group, "CE", prover)
	return
}

func DLEQVerify(group proof.Suite, DLEQproof *dleq.Proof, B kyber.Point, X kyber.Point, xB kyber.Point, xX kyber.Point) (err error) {
	err = DLEQproof.Verify(group, B, X, xB, xX)
	return
}

func CEVerify(group proof.Suite, G, Q, A, B kyber.Point, CEproof []byte) (err error) {
	predCE := proof.And(proof.Rep("A", "r", "G"), proof.Rep("B", "r", "Q", "x", "G"))
	pval := map[string]kyber.Point{"A": A, "G": G, "B": B, "Q": Q}
	verifier := predCE.Verifier(group, pval)
	err = proof.HashVerify(group, "CE", verifier, CEproof)
	return
}
