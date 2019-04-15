package tests

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"sync"
	"testing"

	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/group/nist"
	"go.dedis.ch/kyber/proof"
	"go.dedis.ch/kyber/proof/dleq"

	"github.com/dgamingfoundation/Herb/elgamal"
	"github.com/dgamingfoundation/distributed-key-generation/dkg"
)

func Test_ElGamal_Positive(t *testing.T) {
	testCasesN := []int{3, 5, 10}
	testCasesT := []int{2, 3, 4}
	for i, tc := range testCasesN {
		t.Run(fmt.Sprintf("validators set %d", tc), func(t *testing.T) {
			parties, curve, err := initElGamal(t, tc, testCasesT[i])
			if err != nil {
				t.Errorf("can't init DKG with error %q", err)
			} else {
				elGamalPositive(t, parties, curve, testCasesT[i])
			}
		})
	}
}

func elGamalPositive(t *testing.T, parties []elgamal.Participant, curve proof.Suite, tr int) {
	n := len(parties)

	//Any system user generates some message, encrypts and publishes it
	//We use our validators set (parties) just for example
	publishedCiphertextes := make([]elgamal.Ciphertext, n)
	DLKproofs := make([][]byte, n)
	RKproofs := make([][]byte, n)
	newMessages := make([]kyber.Point, n)
	publishChan := publishMessages(parties, curve)
	for publishedMessage := range publishChan {
		i := publishedMessage.id
		DLKproofs[i] = publishedMessage.DLKproof
		RKproofs[i] = publishedMessage.RKproof
		newMessages[i] = publishedMessage.msg
		publishedCiphertextes[i] = publishedMessage.published
	}
	//verify all ciphertexts by parties[1]
	for i := 0; i < n; i++ {
		errDLK, errRK := parties[1].VerifyCiphertext(curve, DLKproofs[i], publishedCiphertextes[i], RKproofs[i])
		if errDLK != nil {
			t.Errorf("DLK proof isn't verified with error %q", errDLK)
		}
		if errRK != nil {
			t.Errorf("RK proof isn't verified with error %q", errRK)
		}
	}

	//	for i := range publishedCiphertextes {
	//		if !publishedCiphertextes[i].IsValid(curve) {
	//			t.Errorf("Ciphertext is not valid: %v\nOriginal message: %v", publishedCiphertextes[i], newMessages[i])
	//		}
	//	}
	//aggregate all ciphertextes
	commonCiphertext := elgamal.AggregateCiphertext(curve, publishedCiphertextes)

	//if !commonCiphertext.IsValid(curve) {
	//	t.Errorf("Common ciphertext is not valid: %v\nOriginal messages: %v", commonCiphertext, newMessages)
	//}

	//decrypt the random
	decryptParts := make([]kyber.Point, tr)
	DLEproofs := make([]*dleq.Proof, tr)
	verKeys := make([]kyber.Point, tr)
	decrypted := decryptMessages(parties, curve, commonCiphertext, tr)
	for msg := range decrypted {
		i := msg.id
		decryptParts[i] = msg.msg
		DLEproofs[i] = msg.DLEproof
		verKeys[i] = msg.H
	}
	//verify decrypted parts
	for i := 0; i < tr; i++ {
		errDLE := parties[1].VerifyDecParts(curve, DLEproofs[i], commonCiphertext, decryptParts[i], verKeys[i])
		if errDLE != nil {
			t.Errorf("DLE proof isn't verified with error %q", errDLE)
		}
	}
	decryptedMessage := elgamal.Decrypt(curve, commonCiphertext, decryptParts, n)

	expectedMessage := curve.Point().Null()
	for i := range newMessages {
		expectedMessage = curve.Point().Add(expectedMessage, newMessages[i])
	}

	if !decryptedMessage.Equal(expectedMessage) {
		err := errors.New("decryptedMessage isn't equal with expectedMessage")
		t.Errorf("messages isn't equal %q", err)
	}
}

type errorf interface {
	Errorf(format string, args ...interface{})
}

func getBytes(data interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(data)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func getInterface(bts []byte, data interface{}) error {
	buf := bytes.NewBuffer(bts)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(data)
	if err != nil {
		return err
	}
	return nil
}

func initElGamal(t errorf, n int, tr int) ([]elgamal.Participant, proof.Suite, error) {
	// creating elliptic curve
	suite := nist.NewBlakeSHA256P256()

	//generating key
	keyShares, err := dkg.DKG("P256", n, tr)
	if err != nil {
		return nil, nil, err
	}
	participants := make([]elgamal.Participant, n)
	for i, share := range keyShares {
		participants[i].ID = i + 1
		partialKeyBytes, errPK := getBytes(share.PriShare().V)
		if errPK != nil {
			return nil, nil, errPK
		}
		commonKeyBytes, errCK := getBytes(share.Public())
		if errCK != nil {
			return nil, nil, errPK
		}
		participants[i].PartialKey = suite.Scalar()
		participants[i].CommonKey = suite.Point()
		err := getInterface(partialKeyBytes, participants[i].PartialKey)
		if err != nil {
			return nil, nil, err
		}
		err = getInterface(commonKeyBytes, participants[i].CommonKey)
		if err != nil {
			return nil, nil, err
		}
	}
	return participants, suite, nil
}

type publishedMessage struct {
	id        int
	msg       kyber.Point
	published elgamal.Ciphertext
	DLKproof  []byte
	RKproof   []byte
}

func publishMessages(parties []elgamal.Participant, curve proof.Suite) chan publishedMessage {
	publish := make(chan publishedMessage, len(parties))

	wg := sync.WaitGroup{}

	go func() {
		wg.Add(len(parties))

		for i := range parties {
			go func(id int) {
				encryptedMessage, message, DLKproof, RKproof, _, _ := parties[id].Encrypt(curve)

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
	H        kyber.Point
}

func decryptMessages(participant []elgamal.Participant, curve proof.Suite, commonCiphertext elgamal.Ciphertext, tr int) chan decryptedMessage {
	parties := participant[:tr]
	decrypted := make(chan decryptedMessage, len(parties))

	wg := sync.WaitGroup{}

	go func() {
		wg.Add(len(parties))

		for i := range parties {
			go func(id int) {
				decryptedMsg, DLEpr, H := parties[id].PartialDecrypt(curve, commonCiphertext)

				decrypted <- decryptedMessage{id, decryptedMsg, DLEpr, H}
				wg.Done()
			}(i)
		}

		wg.Wait()
		close(decrypted)
	}()

	return decrypted
}
