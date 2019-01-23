package elgamal

import (
	"crypto/elliptic"
	"fmt"
	"testing"
)

func BenchmarkElgamal(b *testing.B) {
	testCases := []int{1, 2, 3, 5, 10, 50, 100, 300}
	for _, tc := range testCases {
		b.Run(fmt.Sprintf("validators set %d", tc), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				curve := elliptic.P256()

				b.StartTimer()
				decryptedMessage, newMessages := elgamalBench(b, tc, curve)
				b.StopTimer()

				expectedMessage := AggregateKeysToPoint(curve, newMessages)
				deepEqual(b, decryptedMessage, expectedMessage)
			}
		})
	}
}

func elgamalBench(b *testing.B, n int, curve elliptic.Curve) (Point, []Point) {
	//generating key
	parties := DKG(curve, n)

	//Any system user generates some message, encrypts and publishes it
	//We use our validators set (parties) just for example
	publishedCiphertextes := make([]Ciphertext, n)

	newMessages := make([]Point, n)
	for i := range publishedCiphertextes {
		newMessages[i] = NewPoint(curve)
		publishedCiphertextes[i] = parties[i].Encrypt(curve, newMessages[i])
	}

	//aggregate all ciphertextes
	commonCiphertext := AggregateCiphertext(curve, publishedCiphertextes)

	//decrypt the random
	decryptParts := make([]Point, n)
	for i := range parties {
		decryptParts[i] = parties[i].PartialDecrypt(curve, commonCiphertext)
	}

	return commonCiphertext.Decrypt(curve, decryptParts), newMessages
}