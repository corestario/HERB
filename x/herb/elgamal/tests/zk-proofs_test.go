package tests

import (
	"testing"

	"github.com/corestario/HERB/x/herb/elgamal"
	"go.dedis.ch/kyber/v3/group/nist"
)

func Test_CEproof_Positive(t *testing.T) {
	suite := nist.NewBlakeSHA256P256()
	G := suite.Point().Base()
	Q := suite.Point().Mul(suite.Scalar().SetInt64(25), G)
	testCases := []int64{-1, 0, 1, 5, 342545}
	for _, y := range testCases {
		t.Run("start", func(t *testing.T) {
			r := suite.Scalar().SetInt64(y)
			x := suite.Scalar().SetInt64(y - 1)
			A := suite.Point().Mul(r, G)
			B := suite.Point().Add(suite.Point().Mul(r, Q), suite.Point().Mul(x, G))
			CEproof, err := elgamal.CE(suite, G, Q, A, B, r, x)
			if err != nil {
				t.Errorf("can't doing ZKProof with error %q", err)
			}
			res := elgamal.CEVerify(suite, G, Q, A, B, CEproof)
			if res != nil {
				t.Errorf("Zkproof isn't valid because of %q", res)
			}
		})
	}
}

func Test_DLEQproof_Positive(t *testing.T) {
	suite := nist.NewBlakeSHA256P256()
	B := suite.Point().Base()
	X := suite.Point().Mul(suite.Scalar().SetInt64(25), B)
	testCases := []int64{-1, 0, 1, 5, 342545}
	for _, y := range testCases {
		t.Run("start", func(t *testing.T) {
			x := suite.Scalar().SetInt64(y)
			DLEQproof, xB, xX, err := elgamal.DLEQ(suite, B, X, x)
			if err != nil {
				t.Errorf("can't doing ZKProof with error %q", err)
			}
			res := elgamal.DLEQVerify(suite, DLEQproof, B, X, xB, xX)
			if res != nil {
				t.Errorf("Zkproof isn't valid because of %q", res)
			}
		})
	}
}
