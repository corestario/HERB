package tests

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
	"github.com/dgamingfoundation/distributed-key-generation/dkg"
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
			keyShares, verificationKeysDKG, err := dkg.DKG("P256", tc, testCasesT[i])
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
func encCiphertext(group proof.Suite, commonKey kyber.Point) (ct elgamal.Ciphertext, M kyber.Point, DLKproof []byte, RKproof []byte, err error) {
	y := group.Scalar().Pick(random.New())
	M = group.Point().Mul(y, nil)
	r := group.Scalar().Pick(random.New())
	S := group.Point().Mul(r, commonKey)
	A := group.Point().Mul(r, nil)
	B := S.Add(group.Point().Mul(r, commonKey), M)
	ct = elgamal.Ciphertext{A, B}
	DLKproof, err = elgamal.DLK(group, group.Point().Base(), r, ct.PointA)
	if err != nil {
		return
	}
	RKproof, err = elgamal.RK(group, group.Point().Base(), y, commonKey, r, ct.PointB)
	return
}
func elGamalPositive(t *testing.T, shares []*kyberDKG.DistKeyShare, verkeys []*kyber.Point, curve proof.Suite, tr int) {
	n := len(shares)

	//Any system user generates some message, encrypts and publishes it
	//We use our validators set (parties) just for example
	publishedCiphertextes := make([]elgamal.Ciphertext, n)
	DLKproofs := make([][]byte, n)
	RKproofs := make([][]byte, n)
	newMessages := make([]kyber.Point, n)
	publishChan := publishMessages(shares, curve)
	for publishedMessage := range publishChan {
		i := publishedMessage.id
		DLKproofs[i] = publishedMessage.DLKproof
		RKproofs[i] = publishedMessage.RKproof
		newMessages[i] = publishedMessage.msg
		publishedCiphertextes[i] = publishedMessage.published
	}
	//verify all ciphertexts by parties[1]
	for i := 0; i < n; i++ {
		errDLK := elgamal.DLKVerify(curve, publishedCiphertextes[i].PointA, curve.Point().Base(), DLKproofs[i])
		if errDLK != nil {
			t.Errorf("DLK proof isn't verified with error %q", errDLK)
		}
		errRK := elgamal.RKVerify(curve, publishedCiphertextes[i].PointB, curve.Point().Base(), shares[i].Public(), RKproofs[i])
		if errRK != nil {
			t.Errorf("RK proof isn't verified with error %q", errRK)
		}
	}

	//aggregate all ciphertextes
	commonCiphertext := elgamal.AggregateCiphertext(curve, publishedCiphertextes)

	//decrypt the random
	decryptParts := make([]kyber.Point, tr)
	DLEproofs := make([]*dleq.Proof, tr)
	decrypted := decryptMessages(shares, curve, commonCiphertext, tr)
	for msg := range decrypted {
		i := msg.id
		decryptParts[i] = msg.msg
		DLEproofs[i] = msg.DLEproof
	}
	//verify decrypted parts
	for i := 0; i < tr; i++ {
		errDLE := elgamal.DLEVerify(curve, DLEproofs[i], curve.Point().Base(), commonCiphertext.PointA, *verkeys[i], decryptParts[i])
		if errDLE != nil {
			t.Errorf("DLE proof isn't verified with error %q", errDLE)
		}
	}
	decryptShares := make([]*share.PubShare, 0)
	for i := 0; i < tr; i++ {
		decryptShares = append(decryptShares, &share.PubShare{I: i, V: decryptParts[i]})
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
	DLKproof  []byte
	RKproof   []byte
}

func publishMessages(shares []*kyberDKG.DistKeyShare, curve proof.Suite) chan publishedMessage {
	publish := make(chan publishedMessage, len(shares))

	wg := sync.WaitGroup{}
	wg.Add(len(shares))

	go func() {

		for i := range shares {
			go func(id int) {
				encryptedMessage, message, DLKproof, RKproof, _ := encCiphertext(curve, shares[id].Public())
				publish <- publishedMessage{id, message, encryptedMessage, DLKproof, RKproof}
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
	DLEproof *dleq.Proof
}

func decryptMessages(shares []*kyberDKG.DistKeyShare, curve proof.Suite, commonCiphertext elgamal.Ciphertext, tr int) chan decryptedMessage {
	parties := shares[:tr]
	decrypted := make(chan decryptedMessage, len(parties))

	wg := sync.WaitGroup{}
	wg.Add(len(parties))

	go func() {

		for i := range parties {
			go func(id int) {
				decryptedMsg, DLEpr, _ := elgamal.CreateDecShare(curve, commonCiphertext, shares[id].PriShare().V)
				decrypted <- decryptedMessage{id, decryptedMsg, DLEpr}
				wg.Done()
			}(i)
		}

		wg.Wait()
		close(decrypted)
	}()

	return decrypted
}
