package tests

import (
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

/*func Test_IdentityCiphertext_Positive(t *testing.T) {
	curve := elliptic.P256()
	party, err := DKG(curve, 1)
	if err != nil {
		t.Errorf("can't init DKG with error %q", err)
	}

	genPoint, err := point.FromCoordinates(curve, curve.Params().Gx, curve.Params().Gy)
	if err != nil {
		t.Errorf("can't make genPoint: %s", err)
	}

	n1 := big.NewInt(1)
	n1.Sub(curve.Params().N, big.NewInt(1))

	messages := []point.Point{point.PointAtInfinity(curve), genPoint,
		genPoint.ScalarMult(curve, big.NewInt(13)), genPoint.ScalarMult(curve, n1)}

	testCases := make([]Ciphertext, len(messages))
	for i, m := range messages {
		testCases[i] = party[0].Encrypt(curve, m)
	}

	neutralCiphertext := IdentityCiphertext(curve)
	for i, tc := range testCases {
		t.Run(fmt.Sprintf("Ciphertext %d:", i), func(t *testing.T) {
			neutralCiphertextAggregate(t, curve, tc, neutralCiphertext, party[0])
		})
	}
}*/

/*func neutralCiphertextAggregate(t *testing.T, curve elliptic.Curve, ct Ciphertext, neutral Ciphertext, party Participant) {
	parts := []Ciphertext{ct, neutral}
	resultCT := AggregateCiphertext(curve, parts)

	originalDecryptShares := []point.Point{party.PartialDecrypt(curve, ct)}
	plaintext := ct.Decrypt(curve, originalDecryptShares)

	newDecryptShares := []point.Point{party.PartialDecrypt(curve, resultCT)}
	resultPlaintext := resultCT.Decrypt(curve, newDecryptShares)

	deepEqual(t, resultPlaintext, plaintext)
}

func scalarMultPositive(t *testing.T, curve elliptic.Curve, p point.Point, pointInf point.Point) {
	curveParams := curve.Params()
	multResult := p.ScalarMult(curve, curveParams.N)
	deepEqual(t, pointInf, multResult)
}

func addPositive(t *testing.T, curve elliptic.Curve, p point.Point, pointInf point.Point) {
	addResult := p.Add(curve, pointInf)
	deepEqual(t, p, addResult)
}

func subPositive(t *testing.T, curve elliptic.Curve, p point.Point, pointInf point.Point) {
	subResult := p.Sub(curve, pointInf)
	deepEqual(t, p, subResult)
}

func subTwoEqualPositive(t *testing.T, curve elliptic.Curve, p point.Point, pointInf point.Point) {
	fmt.Println(p.GetX(), p.GetY())
	subResult := p.Sub(curve, p)
	fmt.Println(p.GetX(), p.GetY(), subResult.GetX(), subResult.GetY())
	deepEqual(t, pointInf, subResult)
}*/

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
	for i, _ := range newMessages {
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

func initElGamal(t errorf, n int, tr int) ([]elgamal.Participant, proof.Suite, error) {
	// creating elliptic curve
	suite := nist.NewBlakeSHA256P256()

	//generating key
	parties, err := dkg.DKG(suite, n, tr)
	if err != nil {
		return nil, nil, err
	}
	participants := make([]elgamal.Participant, n)
	for i, p := range parties {
		keyShare, err := p.DistKeyShare()
		if err != nil {
			return nil, nil, err
		}
		participants[i].ID = 1
		participants[i].PartialKey = keyShare.PriShare().V
		participants[i].CommonKey = keyShare.Public()
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
				//M := []byte("ILSON")
				//message := curve.Point().Embed(M, random.New())
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
