package point

import (
	"crypto/elliptic"
	"fmt"
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

	getTestCase := func(curve elliptic.Curve) []testCase {
		n1 := big.NewInt(1)
		n1.Sub(curve.Params().N, big.NewInt(1))

		genPoint := Point{curve.Params().Gx, curve.Params().Gy}
		testPoints := []Point{
			PointAtInfinity(curve),
			genPoint,
			genPoint.ScalarMult(curve, big.NewInt(13)),
			genPoint.ScalarMult(curve, n1),
		}

		var testCases []testCase
		for _, point := range testPoints {
			testCases = append(testCases,
				testCase{curve, point.GetX(), point.GetY(), point})
		}

		return testCases
	}

	cases := [][]testCase{
		getTestCase(Curve{elliptic.P256()}),
		getTestCase(Curve{elliptic.P384()}),
		getTestCase(Curve{elliptic.P521()}),
	}

	for _, ellipticCase := range cases {
		for _, testCase := range ellipticCase {

			t.Run(fmt.Sprintf("curve %q, point (%v, %v)", testCase.curve.Params().Name, testCase.x, testCase.y),
				func(t *testing.T) {
					point, err := FromCoordinates(testCase.curve, testCase.x, testCase.y)
					if err != nil {
						t.Errorf("can't get point (%s, %s) on curve %v: %q", testCase.x, testCase.y, testCase.curve, err)
					}

					if !testCase.curve.IsOnCurve(testCase.x, testCase.y) {
						t.Errorf("point(%s, %s) is not on the curve: %v", testCase.x.String(), testCase.y.String(), testCase.curve.Params())
					}

					if !point.Equal(testCase.expected) {
						t.Errorf("point %q was expected, got %q", testCase.expected, point)
					}
				})
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
		x := big.NewInt(0)
		var y *big.Int
		if curve.Params().B != big.NewInt(1) {
			y = big.NewInt(1)
		} else {
			y = big.NewInt(2)
		}

		return testCase{
			curve,
			x,
			y,
		}
	}

	cases := []testCase{
		getTestCase(Curve{elliptic.P256()}),
		getTestCase(Curve{elliptic.P384()}),
		getTestCase(Curve{elliptic.P521()}),
	}

	for _, testCase := range cases {
		_, err := FromCoordinates(testCase.curve, testCase.x, testCase.y)
		t.Run(fmt.Sprintf("curve %q, point (%v, %v)", testCase.curve.Params().Name, testCase.x, testCase.y),
			func(t *testing.T) {
				if !strings.Contains(err.Error(), "is not on the curve") {
					t.Errorf("error 'point is not on the curve' expected, got %v", err)
				}
			})
	}
}
