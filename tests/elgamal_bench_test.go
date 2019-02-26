package tests

import (
	"errors"
	"fmt"
	"testing"

	"github.com/dgamingfoundation/Herb/elgamal"
	"go.dedis.ch/kyber"
)

func BenchmarkElGamal(b *testing.B) {
	testCasesN := []int{2, 3, 5, 10, 50, 100}
	testCasesT := []int{1, 2, 3, 4, 35, 50}
	for j, tc := range testCasesN {
		b.Run(fmt.Sprintf("validators set %d", tc), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				parties, curve, er := initElGamal(b, tc, testCasesT[j])
				if er != nil {
					b.Errorf("can't init DKG with error %q", er)
				} else {
					b.StartTimer()
					decryptedMessage, newMessages := elGamalBench(parties, curve, testCasesT[j])
					b.StopTimer()

					expectedMessage := curve.Point().Null()
					for i, _ := range newMessages {
						expectedMessage = curve.Point().Add(expectedMessage, newMessages[i])
					}

					if !decryptedMessage.Equal(expectedMessage) {
						err := errors.New("decryptedMessage isn't equal with expectedMessage")
						b.Errorf("messages isn't equal %q", err)
					}
				}
			}
		})
	}
}

func elGamalBench(parties []elgamal.Participant, curve kyber.Group, tr int) (kyber.Point, []kyber.Point) {
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

	//aggregate all ciphertextes
	commonCiphertext := elgamal.AggregateCiphertext(curve, publishedCiphertextes)

	//decrypt the random
	decryptParts := make([]kyber.Point, tr)
	decrypted := decryptMessages(parties, curve, commonCiphertext, tr)
	for msg := range decrypted {
		i := msg.id
		decryptParts[i] = msg.msg
	}

	return elgamal.Decrypt(curve, commonCiphertext, decryptParts, n), newMessages
}
