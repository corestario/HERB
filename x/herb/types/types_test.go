package types

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
	"github.com/tendermint/tendermint/crypto/ed25519"
	"go.dedis.ch/kyber/v3/group/nist"
)

//delete in future
/*func TestPlay(t *testing.T) {
	suite := nist.NewBlakeSHA256P256()
	g1 := suite.Point().Base()
	g2 := suite.Point().Mul(suite.Scalar().SetInt64(2), g1)
	ct := elgamal.Ciphertext{g1, g2}
	ctBytes, err := ModuleCdc.MarshalJSON(ct)
	if err != nil {
		t.Errorf("failed to json: %v", err)
	}
	var newct elgamal.Ciphertext
	err2 := ModuleCdc.UnmarshalJSON(ctBytes, newct)
	if err2 != nil {
		t.Errorf("failed from json: %v", err2)
	}
	if ct.Equal(newct) {
		t.Errorf("ciphertexts don't equal")
	}
}*/

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
	ctPartBytes, err3 := ModuleCdc.MarshalJSON(ctPartJSON)
	if err3 != nil {
		t.Errorf("failed marshal: %v", err3)
	}
	var newctPartJSON CiphertextPartJSON
	err4 := ModuleCdc.UnmarshalJSON(ctPartBytes, &newctPartJSON)
	if err4 != nil {
		t.Errorf("failed unmarshal: %v", err4)
	}
	newctPart, err2 := newctPartJSON.Deserialize()
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