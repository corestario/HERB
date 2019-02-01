package elgamal

import (
	"crypto/elliptic"
	"math/big"
	"strings"
	"testing"
)

func Test_FromCoordinates_PointOnCurve_Success(t *testing.T) {
	type testCase struct {
		curve    elliptic.Curve
		x        *big.Int
		y        *big.Int
		expected Point
	}

	getTestCase := func(curve elliptic.Curve) testCase {
		x := curve.Params().Gx
		y := curve.Params().Gy

		return testCase{
			curve,
			x,
			y,
			Point{x, y},
		}
	}

	cases := []testCase{
		getTestCase(elliptic.P256()),
		getTestCase(elliptic.P384()),
		getTestCase(elliptic.P521()),
	}

	for _, testCase := range cases {
		point, err := FromCoordinates(testCase.curve, testCase.x, testCase.y)
		if err != nil {
			t.Errorf("can't get point (%s, %s) on curve %v: %q", testCase.x, testCase.y, testCase.curve, err)
		}

		if !point.IsEqual(testCase.expected) {
			t.Errorf("point %q was expected, got %q", testCase.expected, point)
		}
	}
}

func Test_FromCoordinates_PointOnNotCurve_Fail(t *testing.T) {
	type testCase struct {
		curve elliptic.Curve
		x     *big.Int
		y     *big.Int
	}

	getTestCase := func(curve elliptic.Curve) testCase {
		x := big.NewInt(2)
		y := big.NewInt(2)

		return testCase{
			curve,
			x,
			y,
		}
	}

	cases := []testCase{
		getTestCase(elliptic.P256()),
		getTestCase(elliptic.P384()),
		getTestCase(elliptic.P521()),
	}

	for _, testCase := range cases {
		_, err := FromCoordinates(testCase.curve, testCase.x, testCase.y)
		if !strings.Contains(err.Error(), "is not on the curve") {
			t.Errorf("error 'point is not on the curve' expected, got %v", err)
		}
	}
}
