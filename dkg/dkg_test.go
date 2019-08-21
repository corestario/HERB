package dkg

import (
	"bytes"
	"fmt"
	"testing"

	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"

	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"

	kyberdkg "go.dedis.ch/kyber/v3/share/dkg/rabin"
)

func Test_BLSDKG_Positive(t *testing.T) {
	testCasesN := []int{3, 5, 10}
	testCasesT := []int{2, 3, 4}
	for i, tc := range testCasesN {
		t.Run(fmt.Sprintf("validators set %d", tc), func(t *testing.T) {
			DemoBLSDKG(t, tc, testCasesT[i])
		})
	}
}

func DemoBLSDKG(t *testing.T, n int, threshold int) {
	suiteG1 := bn256.NewSuiteG1()
	parties, _, err := RabinDKGSimulator("bn256.G2", n, threshold)
	if err != nil {
		t.Errorf("RabinDKGSimulator error: %q", err)
		return
	}
	msg := []byte("Hello World")
	group1 := parties[0 : len(parties)-1]
	sign1, err := commonSignature(group1, suiteG1, msg, threshold, n)
	if err != nil {
		t.Errorf("Common signature for the first group %q", err)
		return
	}
	publicKey := parties[0].Public()
	err = bls.Verify(suiteG1, publicKey, msg, sign1)
	if err != nil {
		t.Errorf("Verification first group signature: %q", err)
		return
	}

	group2 := parties[1:]
	sign2, err := commonSignature(group2, suiteG1, msg, threshold, n)
	if err != nil {
		t.Errorf("Common signature for the second group %q", err)
		return
	}
	err = bls.Verify(suiteG1, publicKey, msg, sign2)
	if err != nil {
		t.Errorf("Verification second group signature: %q", err)
		return
	}

	if !bytes.Equal(sign1, sign2) {
		t.Errorf("Signatures are not equal")
		return
	}

}

// generate common TBLS signature for the set of distKeyShares
func commonSignature(distKeyShares []*kyberdkg.DistKeyShare, suite pairing.Suite, msg []byte, t int, n int) ([]byte, error) {
	signatures := make([][]byte, 0)
	for _, keyShare := range distKeyShares {
		sign, err := tbls.Sign(suite, keyShare.PriShare(), msg)
		if err != nil {
			return nil, err
		}
		signatures = append(signatures, sign)
	}
	pubPoly := share.NewPubPoly(suite.G2(), nil, distKeyShares[0].Commitments())
	common, err := tbls.Recover(suite, pubPoly, msg, signatures, t, n)
	if err != nil {
		return nil, err
	}
	return common, nil
}
