package types

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
	"github.com/dgamingfoundation/arcade/crypto/ed25519"
	"go.dedis.ch/kyber/group/nist"
)

func TestSerialization(t *testing.T) {
	suite := nist.NewBlakeSHA256P256()
	g1 := suite.Point().Base()
	g2 := suite.Point().Mul(suite.Scalar().SetInt64(2), g1)
	ct := elgamal.Ciphertext{g1, g2}
	userPk1 := ed25519.GenPrivKey().PubKey()
	userAddr1 := sdk.AccAddress(userPk1.Address())
	ctPart := CiphertextPart{ct, userAddr1}
	ctPartJSON, err := NewCiphertextPartJSON(&ctPart)
	if err != nil {
		t.Errorf("failed to json: %v", err)
	}
	newctPart, err2 := ctPartJSON.PartDeserialize()
	if err2 != nil {
		t.Errorf("failed to json: %v", err2)
	}
	if !ctPart.EntropyProvider.Equals(newctPart.EntropyProvider) {
		t.Errorf("addresses don't equal")
	}
	if !ctPart.Ciphertext.Equal(newctPart.Ciphertext) {
		t.Errorf("ciphertexts don't equal")
	}
}
