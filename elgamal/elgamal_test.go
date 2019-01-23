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
	testCases := []int{1,2,3,5,10,50,100,300}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("validators set %d", tc), func(t *testing.T) {
			elgamalPositive(t, tc)
		})
	}
}

func elgamalPositive(t *testing.T, n int) {
	// creating elliptic curve
	E := elliptic.P256()

	//generating key
	parties := DKG(E, n)

	//Any system user generates some message, encrypts and publishes it
	//We use our validators set (parties) just for example
	publishedCiphertextes := make([]Ciphertext, n)

	newMessages := make([]Point, n)
	for i := range publishedCiphertextes {
		newMessages[i] = GeneratePoint(E)
		publishedCiphertextes[i] = parties[i].Encrypt(E, newMessages[i])
	}

	for i := range publishedCiphertextes {
		if !IsValidCiphertext(publishedCiphertextes[i], E) {
			t.Errorf("Ciphertext is not valid: %v\nOriginal message: %v", publishedCiphertextes[i], newMessages[i])
		}
	}

	//aggregate all ciphertextes
	commonCiphertext := AggregateCiphertext(E, publishedCiphertextes)

	if !IsValidCiphertext(commonCiphertext, E) {
		t.Errorf("Common ciphertext is not valid: %v\nOriginal messages: %v", commonCiphertext, newMessages)
	}

	//decrypt the random
	decryptParts := make([]Point, n)
	for i := range parties {
		decryptParts[i] = parties[i].PartialDecrypt(E, commonCiphertext)
	}

	decryptedMessage := DecryptFromShares(E, decryptParts, commonCiphertext)

	expectedMessage := AggregateKeysToPoint(E, newMessages)

	deepEqual(t, decryptedMessage, expectedMessage)
}

func deepEqual(t *testing.T, obtained, expected interface{}) {
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
