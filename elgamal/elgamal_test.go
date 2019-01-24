package elgamal

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
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
	if !reflect.DeepEqual(obtained, expected) {
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
