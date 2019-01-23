package elgamal

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
	"reflect"
	"testing"

	"github.com/kr/pretty"
)

func Test_Elgamal_Positive(t *testing.T) {
	testCases := []int{1, 2, 3, 5, 10, 50, 100, 300}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("validators set %d", tc), func(t *testing.T) {
			elgamalPositive(t, tc)
		})
	}
}

func elgamalPositive(t *testing.T, n int) {
	// creating elliptic curve
	curve := elliptic.P256()

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
	for i := range parties {
		decryptParts[i] = parties[i].PartialDecrypt(curve, commonCiphertext)
	}

	decryptedMessage := commonCiphertext.Decrypt(curve, decryptParts)

	expectedMessage := AggregateKeysToPoint(curve, newMessages)

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
