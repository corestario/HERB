package tests

import (
	"errors"
	"math/big"
	"testing"

	"github.com/dgamingfoundation/Herb/elgamal"
	"go.dedis.ch/kyber/group/nist"
)

func Test_DLKproof_Positive(t *testing.T) {
	suite := nist.NewBlakeSHA256P256()
	B := suite.Point().Base()
	testCases := []int64{-1, 0, 1, 5, 342545}
	for _, y := range testCases {
		t.Run("start", func(t *testing.T) {
			x := suite.Scalar().SetInt64(y)
			X := suite.Point().Mul(x, nil)
			DLKproof, predDLK, err := elgamal.DLK(suite, B, x, X)
			if err != nil {
				t.Errorf("can't doing ZKProof with error %q", err)
			}
			res := elgamal.DLKVerify(suite, X, B, predDLK, DLKproof)
			if res != nil {
				t.Errorf("Zkproof isn't valid because of %q", res)
			}
		})
	}
}

//(N-1)*B == -1*B in kyber ?
func Test_EqualityPoints_Positive(t *testing.T) {
	suite := nist.NewBlakeSHA256P256()
	t.Run("start", func(t *testing.T) {
		z := new(big.Int).Sub(suite.Order(), big.NewInt(1))
		A := suite.Point().Mul(suite.Scalar().SetInt64(-1), suite.Point().Base())
		B := suite.Point().Mul(suite.Scalar().SetBytes(z.Bytes()), suite.Point().Base())
		if !A.Equal(B) {
			err := errors.New("(N-1)Base != -1Base")
			t.Errorf("Equality isn't satisfied with error %q", err)
		}
	})
}
