package elgamal

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"reflect"
	"sync"
	"testing"

	"github.com/kr/pretty"
)

func Test_ElGamal_Positive(t *testing.T) {
	testCases := []int{1, 2, 3, 5, 10, 50, 100, 300}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("validators set %d", tc), func(t *testing.T) {
			parties, curve := initElGamal(tc)
			elGamalPositive(t, parties, curve)
		})
	}
}

func Test_PointAtInfinity_Positive(t *testing.T) {
	curve := elliptic.P256()
	curveParams := curve.Params()
	genPoint := Point{curveParams.Gx, curveParams.Gy}
	//I just try to get the value of N
	//n := big.NewInt(1)
	//*n = *curveParams.N
	//genPoint.scalarMult(curve, n.Sub(n, big.NewInt(1)))
	testCases := []Point{genPoint, genPoint.scalarMult(curve, big.NewInt(13))}
	pointInf := PointAtInfinity(curve)
	for i, tc := range testCases {
		t.Run(fmt.Sprintf("Scalar multiplication, point %d * G:", i), func(t *testing.T) {
			scalarMultPositive(t, curve, tc, pointInf)
		})
		t.Run(fmt.Sprintf("Addition, point %d:", i), func(t *testing.T) {
		})
		t.Run(fmt.Sprintf("Substraction, point %d:", i), func(t *testing.T) {
			subPositive(t, curve, tc, pointInf)
		})
	}
}

func Test_IdentityCiphertext_Positive(t *testing.T) {
	curve := elliptic.P256()
	party := DKG(curve, 1)
	genPoint := Point{curve.Params().Gx, curve.Params().Gy}
	//I just try to get the value of N, probably there is more convenient way to do it
	//n := big.NewInt(1)
	//*n = *curve.Params().N
	//genPoint.scalarMult(curve, n.Sub(n, big.NewInt(1)))
	messages := []Point{PointAtInfinity(curve), genPoint, genPoint.scalarMult(curve, big.NewInt(13))}
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
}

func neutralCiphertextAggregate(t *testing.T, curve elliptic.Curve, ct Ciphertext, neutral Ciphertext, party Participant) {
	parts := []Ciphertext{ct, neutral}
	resultCT := AggregateCiphertext(curve, parts)
	originalDecryptShares := []Point{party.PartialDecrypt(curve, ct)}
	plaintext := ct.Decrypt(curve, originalDecryptShares)
	newDecryptShares := []Point{party.PartialDecrypt(curve, resultCT)}
	resultPlaintext := resultCT.Decrypt(curve, newDecryptShares)
	deepEqual(t, resultPlaintext, plaintext)
}

func scalarMultPositive(t *testing.T, curve elliptic.Curve, p Point, pointInf Point) {
	/*z := randBigInt(curve)
	z.SetInt64(5)*/
	curveParams := curve.Params()
	multResult := p.scalarMult(curve, curveParams.N)
	deepEqual(t, pointInf, multResult)
}

func addPositive(t *testing.T, curve elliptic.Curve, p Point, pointInf Point) {
	addResult := p.add(curve, pointInf)
	deepEqual(t, p, addResult)
}

func subPositive(t *testing.T, curve elliptic.Curve, p Point, pointInf Point) {
	subResult := p.sub(curve, pointInf)
	deepEqual(t, p, subResult)
}

func elGamalPositive(t *testing.T, parties []Participant, curve elliptic.Curve) {
	n := len(parties)

	//Any system user generates some message, encrypts and publishes it
	//We use our validators set (parties) just for example
	publishedCiphertextes := make([]Ciphertext, n)

	newMessages := make([]Point, n)
	publishChan := publishMessages(parties, curve)
	for publishedMessage := range publishChan {
		i := publishedMessage.id

		newMessages[i] = publishedMessage.msg
		publishedCiphertextes[i] = publishedMessage.published
	}

	for i := range publishedCiphertextes {
		if !publishedCiphertextes[i].IsValid(curve) {
			t.Errorf("Ciphertext is not valid: %v\nOriginal message: %v", publishedCiphertextes[i], newMessages[i])
		}
	}

	//aggregate all ciphertextes
	commonCiphertext := AggregateCiphertext(curve, publishedCiphertextes)

	if !commonCiphertext.IsValid(curve) {
		t.Errorf("Common ciphertext is not valid: %v\nOriginal messages: %v", commonCiphertext, newMessages)
	}

	//decrypt the random
	decryptParts := make([]Point, n)
	decrypted := decryptMessages(parties, curve, commonCiphertext)
	for msg := range decrypted {
		i := msg.id
		decryptParts[i] = msg.msg
	}

	decryptedMessage := commonCiphertext.Decrypt(curve, decryptParts)

	expectedMessage := RecoverPoint(curve, newMessages)

	deepEqual(t, decryptedMessage, expectedMessage)
}

type errorf interface {
	Errorf(format string, args ...interface{})
}

func deepEqual(t errorf, obtained, expected interface{}) {
	var ok bool
	switch valueA := expected.(type) {
	case Point:
		var valueB Point
		valueB, ok = obtained.(Point)
		if ok {
			ok = valueA.IsEqual(valueB)
		}
	case Ciphertext:
		var valueB Ciphertext
		valueB, ok = obtained.(Ciphertext)
		if ok {
			ok = valueA.IsEqual(valueB)
		}
	case KeyPair:
		var valueB KeyPair
		valueB, ok = obtained.(KeyPair)
		if ok {
			ok = valueA.IsEqual(valueB)
		}
	case Participant:
		var valueB Participant
		valueB, ok = obtained.(Participant)
		if ok {
			ok = valueA.IsEqual(valueB)
		}
	case ZKproof:
		var valueB ZKproof
		valueB, ok = obtained.(ZKproof)
		if ok {
			ok = valueA.IsEqual(valueB)
		}
	}


	// If we can't use IsEqual methods, we call DeepReflect
	if !ok && !reflect.DeepEqual(obtained, expected) {
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
}

func initElGamal(n int) ([]Participant, elliptic.Curve) {
	// creating elliptic curve
	curve := elliptic.P256()

	//generating key
	return DKG(curve, n), curve
}

type publishedMessage struct {
	id        int
	msg       Point
	published Ciphertext
}

func publishMessages(parties []Participant, curve elliptic.Curve) chan publishedMessage {
	publish := make(chan publishedMessage, len(parties))

	wg := sync.WaitGroup{}

	go func() {
		wg.Add(len(parties))

		for i := range parties {
			go func(id int) {
				message := NewPoint(curve)
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
	msg Point
}

func decryptMessages(parties []Participant, curve elliptic.Curve, commonCiphertext Ciphertext) chan decryptedMessage {
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

type pointIsEqual interface {
	IsEqual(p1 Point) bool
}