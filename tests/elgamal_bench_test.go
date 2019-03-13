package tests

import (
	"errors"
	"fmt"
	"testing"

	"github.com/dgamingfoundation/Herb/elgamal"
	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/proof"
	"go.dedis.ch/kyber/proof/dleq"
)

func BenchmarkElGamal(b *testing.B) {
	testCasesN := []int{3, 5, 10}
	testCasesT := []int{2, 3, 4}
	for j, tc := range testCasesN {
		b.Run(fmt.Sprintf("validators set %d", tc), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				parties, curve, er := initElGamal(b, tc, testCasesT[j])
				if er != nil {
					b.Errorf("can't init DKG with error %q", er)
				} else {
					b.StartTimer()
					decryptedMessage, newMessages, errDLE, errDLK, errRK := elGamalBench(parties, curve, testCasesT[j])
					//decryptedMessage, newMessages, _, _, _ := elGamalBench(parties, curve, testCasesT[j])
					b.StopTimer()
					for i, err := range errDLK {
						if err != nil {
							b.Errorf("DLK %d-th party isn't valid with error %q", i, err)
						}
						if errRK[i] != nil {
							b.Errorf("RK %d-th party isn't valid with error %q", i, errRK[i])
						}
					}
					for _, err := range errDLE {
						if err != nil {
							b.Errorf("DLE %d-th party isn't valid with error %q", i, err)
						}
					}
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

func elGamalBench(parties []elgamal.Participant, curve proof.Suite, tr int) (kyber.Point, []kyber.Point, []error, []error, []error) {
	n := len(parties)

	//Any system user generates some message, encrypts and publishes it
	//We use our validators set (parties) just for example
	publishedCiphertextes := make([]elgamal.Ciphertext, n)
	DLKproofs := make([][]byte, n)
	RKproofs := make([][]byte, n)
	newMessages := make([]kyber.Point, n)
	errDLK := make([]error, n)
	errRK := make([]error, n)
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
		errDLK[i], errRK[i] = parties[1].VerifyCiphertext(curve, DLKproofs[i], publishedCiphertextes[i], RKproofs[i])
	}
	//aggregate all ciphertextes
	commonCiphertext := elgamal.AggregateCiphertext(curve, publishedCiphertextes)

	//decrypt the random
	decryptParts := make([]kyber.Point, tr)
	DLEproofs := make([]*dleq.Proof, tr)
	verKeys := make([]kyber.Point, tr)
	decrypted := decryptMessages(parties, curve, commonCiphertext, tr)
	errDLE := make([]error, tr)
	for msg := range decrypted {
		i := msg.id
		decryptParts[i] = msg.msg
		DLEproofs[i] = msg.DLEproof
		verKeys[i] = msg.H
	}
	//verify decrypted parts
	for i := 0; i < tr; i++ {
		errDLE[i] = parties[1].VerifyDecParts(curve, DLEproofs[i], commonCiphertext, decryptParts[i], verKeys[i])
	}
	return elgamal.Decrypt(curve, commonCiphertext, decryptParts, n), newMessages, errDLE, errDLK, errRK
}
