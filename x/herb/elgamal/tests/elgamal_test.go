package tests

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/dgamingfoundation/HERB/dkg"
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
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
func elGamalPositive(t *testing.T, shares []*kyberDKG.DistKeyShare, verkeys []*kyber.Point, curve proof.Suite, tr int) {
	n := len(shares)

	//Any system user generates some message, encrypts and publishes it
	//We use our validators set (parties) just for example
	publishedCiphertextes := make([]elgamal.Ciphertext, n)
	CEproofs := make([][]byte, n)
	newMessages := make([]kyber.Point, n)
	publishChan := publishMessages(shares, curve)
	for publishedMessage := range publishChan {
		i := publishedMessage.id
		CEproofs[i] = publishedMessage.CEproof
		newMessages[i] = publishedMessage.msg
		publishedCiphertextes[i] = publishedMessage.published
	}
	//verify all ciphertexts by parties[1]
	for i := 0; i < n; i++ {
		errCE := elgamal.CEVerify(curve, curve.Point().Base(), shares[i].Public(), publishedCiphertextes[i].PointA, publishedCiphertextes[i].PointB, CEproofs[i])
		if errCE != nil {
			t.Errorf("CE proof isn't verified with error %q", errCE)
		}
	}

	//aggregate all ciphertextes
	commonCiphertext := elgamal.AggregateCiphertext(curve, publishedCiphertextes)

	//decrypt the random
	decryptShares := make([]kyber.Point, tr)
	DLEQproofs := make([]*dleq.Proof, tr)
	decrypted := decryptMessages(shares, curve, commonCiphertext, tr)
	for msg := range decrypted {
		i := msg.id
		decryptShares[i] = msg.msg
		DLEQproofs[i] = msg.DLEQproof
	}
	//verify decrypted shares
	for i := 0; i < tr; i++ {
		errDLEQ := elgamal.DLEQVerify(curve, DLEQproofs[i], curve.Point().Base(), commonCiphertext.PointA, *verkeys[i], decryptShares[i])
		if errDLEQ != nil {
			t.Errorf("DLEQ proof isn't verified with error %q", errDLEQ)
		}
	}
	decryptShares := make([]*share.PubShare, 0)
	for i := 0; i < tr; i++ {
		decryptShares = append(decryptShares, &share.PubShare{I: i, V: decryptShares[i]})
	}
	decryptedMessage := elgamal.Decrypt(curve, commonCiphertext, decryptShares, n)

	expectedMessage := curve.Point().Null()
	for i := range newMessages {
		expectedMessage = curve.Point().Add(expectedMessage, newMessages[i])
	}

	if !decryptedMessage.Equal(expectedMessage) {
		err := errors.New("decryptedMessage isn't equal with expectedMessage")
		t.Errorf("messages isn't equal %q", err)
	}
}

type publishedMessage struct {
	id        int
	msg       kyber.Point
	published elgamal.Ciphertext
	CEproof   []byte
}

func publishMessages(shares []*kyberDKG.DistKeyShare, curve proof.Suite) chan publishedMessage {
	publish := make(chan publishedMessage, len(shares))

	wg := sync.WaitGroup{}
	wg.Add(len(shares))

	go func() {

		for i := range shares {
			go func(id int) {
				encryptedMessage, message, CEproof, _ := encCiphertext(curve, shares[id].Public())
				publish <- publishedMessage{id, message, encryptedMessage, CEproof}
				wg.Done()
			}(i)
		}

		wg.Wait()
		close(publish)
	}()

	return publish
}

type decryptedMessage struct {
	id       int
	msg      kyber.Point
	DLEQproof *dleq.Proof
}

func decryptMessages(shares []*kyberDKG.DistKeyShare, curve proof.Suite, commonCiphertext elgamal.Ciphertext, tr int) chan decryptedMessage {
	parties := shares[:tr]
	decrypted := make(chan decryptedMessage, len(parties))

	wg := sync.WaitGroup{}
	wg.Add(len(parties))

	go func() {

		for i := range parties {
			go func(id int) {
				decryptedMsg, DLEQpr, _ := elgamal.CreateDecShare(curve, commonCiphertext, shares[id].PriShare().V)
				decrypted <- decryptedMessage{id, decryptedMsg, DLEQpr}
				wg.Done()
			}(i)
		}

		wg.Wait()
		close(decrypted)
	}()

	return decrypted
}
