package elgamal

import (
	"crypto/elliptic"
	"fmt"
	"testing"
)

func BenchmarkElGamal(b *testing.B) {
	testCases := []int{1, 2, 3, 5, 10, 50, 100, 300}
	for _, tc := range testCases {
		b.Run(fmt.Sprintf("validators set %d", tc), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				parties, curve := initElGamal(tc)

				b.StartTimer()
				decryptedMessage, newMessages := elGamalBench(parties, curve)
				b.StopTimer()

				expectedMessage := RecoverPoint(curve, newMessages)
				deepEqual(b, decryptedMessage, expectedMessage)
			}
		})
	}
}

func elGamalBench(parties []Participant, curve elliptic.Curve) (Point, []Point) {
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

	//aggregate all ciphertextes
	commonCiphertext := AggregateCiphertext(curve, publishedCiphertextes)

	//decrypt the random
	decryptParts := make([]Point, n)
	decrypted := decryptMessages(parties, curve, commonCiphertext)
	for msg := range decrypted {
		i := msg.id
		decryptParts[i] = msg.msg
	}

	return commonCiphertext.Decrypt(curve, decryptParts), newMessages
}
