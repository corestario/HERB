package tests

import (
	"errors"
	"fmt"
	"testing"

	"github.com/corestario/HERB/dkg"
	"github.com/corestario/HERB/x/herb/elgamal"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/nist"
	"go.dedis.ch/kyber/v3/proof"
	"go.dedis.ch/kyber/v3/proof/dleq"
	"go.dedis.ch/kyber/v3/share"
	kyberDKG "go.dedis.ch/kyber/v3/share/dkg/rabin"
	"go.dedis.ch/kyber/v3/util/random"
)

func Test_ElGamal_Positive(t *testing.T) {
	testCasesN := []int{3, 5, 10}
	testCasesT := []int{2, 3, 4}
	for i, tc := range testCasesN {
		t.Run(fmt.Sprintf("validators set %d", tc), func(t *testing.T) {
			suite := nist.NewBlakeSHA256P256()
			keyShares, verificationKeysDKG, err := dkg.RabinDKGSimulator("P256", tc, testCasesT[i])
			if err != nil {
				t.Errorf("DKG failed with error")
			}
			if err != nil {
				t.Errorf("can't init DKG with error %q", err)
			} else {
				elGamalPositive(t, keyShares, verificationKeysDKG, suite, testCasesT[i])
			}
		})
	}
}

func elGamalPositive(t *testing.T, shares []*kyberDKG.DistKeyShare, verkeys []*kyber.Point, curve proof.Suite, tr int) {
	n := len(shares)

	//Any system user generates some message, encrypts and publishes it
	//We use our validators set (parties) just for example
	publishedCiphertextes := make([]elgamal.Ciphertext, n)
	CEproofs := make([][]byte, n)
	newMessages := make([]kyber.Point, n)
	for i := 0; i < n; i++ {
		encryptedMessage, message, CEproof, err := encCiphertext(curve, shares[i].Public())
		if err != nil {
			t.Errorf(fmt.Sprintf("Can't encrypt message, id: %v, err: %v", i, err))
		}
		CEproofs[i] = CEproof
		newMessages[i] = message
		publishedCiphertextes[i] = encryptedMessage
	}

	//verify all ciphertexts by parties[1]
	for i := 0; i < n; i++ {
		err := elgamal.CEVerify(curve, curve.Point().Base(), shares[i].Public(), publishedCiphertextes[i].PointA, publishedCiphertextes[i].PointB, CEproofs[i])
		if err != nil {
			t.Errorf("CE proof isn't verified with error %v", err)
		}
	}

	//aggregate all ciphertextes
	commonCiphertext := elgamal.AggregateCiphertext(curve, publishedCiphertextes)

	//decrypt the random
	decryptShares := make([]kyber.Point, tr)
	DLEQproofs := make([]*dleq.Proof, tr)
	for i := 0; i < tr; i++ {
		decryptedMsg, dleqProof, err := elgamal.CreateDecShare(curve, commonCiphertext, shares[i].PriShare().V)
		if err != nil {
			t.Errorf(fmt.Sprintf("Can't decrypt message, id: %v, err: %v", i, err))
		}
		decryptShares[i] = decryptedMsg
		DLEQproofs[i] = dleqProof
	}
	//verify decrypted shares
	for i := 0; i < tr; i++ {
		errDLEQ := elgamal.DLEQVerify(curve, DLEQproofs[i], curve.Point().Base(), commonCiphertext.PointA, *verkeys[i], decryptShares[i])
		if errDLEQ != nil {
			t.Errorf("DLEQ proof isn't verified with error %q", errDLEQ)
		}
	}
	pubShares := make([]*share.PubShare, 0)
	for i := 0; i < tr; i++ {
		pubShares = append(pubShares, &share.PubShare{I: i, V: decryptShares[i]})
	}
	decryptedMessage := elgamal.Decrypt(curve, commonCiphertext, pubShares, n)

	expectedMessage := curve.Point().Null()
	for i := range newMessages {
		expectedMessage = curve.Point().Add(expectedMessage, newMessages[i])
	}

	if !decryptedMessage.Equal(expectedMessage) {
		err := errors.New("decryptedMessage isn't equal with expectedMessage")
		t.Errorf("messages isn't equal %q", err)
	}
}

func encCiphertext(group proof.Suite, commonKey kyber.Point) (ct elgamal.Ciphertext, M kyber.Point, CEproof []byte, err error) {
	y := group.Scalar().Pick(random.New())
	M = group.Point().Mul(y, nil)
	r := group.Scalar().Pick(random.New())
	S := group.Point().Mul(r, commonKey)
	A := group.Point().Mul(r, nil)
	B := S.Add(group.Point().Mul(r, commonKey), M)
	ct = elgamal.Ciphertext{A, B}
	CEproof, err = elgamal.CE(group, group.Point().Base(), commonKey, ct.PointA, ct.PointB, r, y)
	if err != nil {
		return
	}
	return
}
