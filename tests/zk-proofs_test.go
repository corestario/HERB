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
			DLKproof, err := elgamal.DLK(suite, B, x, X)
			if err != nil {
				t.Errorf("can't doing ZKProof with error %q", err)
			}
			res := elgamal.DLKVerify(suite, X, B, DLKproof)
			if res != nil {
				t.Errorf("Zkproof isn't valid because of %q", res)
			}
		})
	}
}

func Test_RKproof_Positive(t *testing.T) {
	suite := nist.NewBlakeSHA256P256()
	B1 := suite.Point().Base()
	B2 := suite.Point().Mul(suite.Scalar().SetInt64(25), B1)
	testCases := []int64{-1, 0, 1, 5, 342545}
	for _, y := range testCases {
		t.Run("start", func(t *testing.T) {
			x1 := suite.Scalar().SetInt64(y)
			for _, z := range testCases {
				x2 := suite.Scalar().SetInt64(z)
				X := suite.Point().Add(suite.Point().Mul(x1, B1), suite.Point().Mul(x2, B2))
				RKproof, err := elgamal.RK(suite, B1, x1, B2, x2, X)
				if err != nil {
					t.Errorf("can't doing ZKProof with error %q", err)
				}
				res := elgamal.RKVerify(suite, X, B1, B2, RKproof)
				if res != nil {
					t.Errorf("Zkproof isn't valid because of %q", res)
				}
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
