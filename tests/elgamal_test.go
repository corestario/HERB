package tests

import (
	"fmt"
	"sync"
	"testing"

	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/group/nist"
	"go.dedis.ch/kyber/util/random"

	"github.com/dgamingfoundation/Herb/elgamal"
)

func Test_ElGamal_Positive(t *testing.T) {
	testCasesN := []int{2, 3, 5, 10, 50, 100}
	testCasesT := []int{1, 2, 3, 4, 35, 50}
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

func elGamalPositive(t *testing.T, parties []elgamal.Participant, curve kyber.Group, tr int) {
	n := len(parties)

	//Any system user generates some message, encrypts and publishes it
	//We use our validators set (parties) just for example
	publishedCiphertextes := make([]elgamal.Ciphertext, n)

	newMessages := make([]kyber.Point, n)
	publishChan := publishMessages(parties, curve)
	for publishedMessage := range publishChan {
		i := publishedMessage.id

		newMessages[i] = publishedMessage.msg
		publishedCiphertextes[i] = publishedMessage.published
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
	decrypted := decryptMessages(parties, curve, commonCiphertext, tr)
	for msg := range decrypted {
		i := msg.id
		decryptParts[i] = msg.msg
	}

	decryptedMessage := elgamal.Decrypt(curve, commonCiphertext, decryptParts, n)

	expectedMessage := curve.Point().Null()
	for i, _ := range newMessages {
		expectedMessage = curve.Point().Add(expectedMessage, newMessages[i])
	}

	decryptedMessage.Equal(expectedMessage)
}

type errorf interface {
	Errorf(format string, args ...interface{})
}

/*
func deepEqual(t errorf, obtained, expected interface{}) {
	if !cmp.Equal(obtained, expected) {
		t.Errorf("... %s", diff(obtained, expected))
	}
}

func diff(obtained, expected interface{}) string {
	var failMessage bytes.Buffer
	diffs := pretty.Diff(obtained, expected)

	if len(diffs) > 0 {
		failMessage.WriteString("Obtained:\t\tExpected:")
		for _, singleDiff := range diffs {
			failMessage.WriteString(fmt.Sprintf("\n%v", singleDiff))
		}
	}

	return failMessage.String()
}*/

func initElGamal(t errorf, n int, tr int) ([]elgamal.Participant, kyber.Group, error) {
	// creating elliptic curve
	suite := nist.NewBlakeSHA256P256()

	//generating key
	parties, err := elgamal.DKG(suite, n, tr)
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
}

func publishMessages(parties []elgamal.Participant, curve kyber.Group) chan publishedMessage {
	publish := make(chan publishedMessage, len(parties))

	wg := sync.WaitGroup{}

	go func() {
		wg.Add(len(parties))

		for i := range parties {
			go func(id int) {
				M := []byte("ILSON")
				message := curve.Point().Embed(M, random.New())
				encryptedMessage := parties[id].Encrypt(curve, message)

				publish <- publishedMessage{id, message, encryptedMessage}
				wg.Done()
			}(i)
		}

		wg.Wait()
		close(publish)
	}()

	return publish
}

type decryptedMessage struct {
	id  int
	msg kyber.Point
}

func decryptMessages(participant []elgamal.Participant, curve kyber.Group, commonCiphertext elgamal.Ciphertext, tr int) chan decryptedMessage {
	parties := participant[:tr]
	decrypted := make(chan decryptedMessage, len(parties))

	wg := sync.WaitGroup{}

	go func() {
		wg.Add(len(parties))

		for i := range parties {
			go func(id int) {
				decryptedMsg := parties[id].PartialDecrypt(curve, commonCiphertext)

				decrypted <- decryptedMessage{id, decryptedMsg}
				wg.Done()
			}(i)
		}

		wg.Wait()
		close(decrypted)
	}()

	return decrypted
}
