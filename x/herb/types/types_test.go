package types

import (
	"fmt"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
	"github.com/tendermint/tendermint/crypto/ed25519"
	"go.dedis.ch/kyber/v3/group/nist"
	kyberenc "go.dedis.ch/kyber/v3/util/encoding"
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

func TestCiphertextSerialization(t *testing.T) {
	suite := nist.NewBlakeSHA256P256()
	g1 := suite.Point().Base()
	g2 := suite.Point().Mul(suite.Scalar().SetInt64(2), g1)
	ct := elgamal.Ciphertext{g1, g2}
	userPk1 := ed25519.GenPrivKey().PubKey()
	userAddr1 := sdk.AccAddress(userPk1.Address())
	ctPart := CiphertextPart{ct, []byte("example"), []byte("example3"), userAddr1}
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

func TestDecryptionSharesSerialization(t *testing.T) {
	suite := nist.NewBlakeSHA256P256()
	g := suite.Point().Base()
	x := suite.Scalar().SetInt64(2)
	g1 := suite.Point().Mul(x, g)
	g2 := suite.Point().Mul(x, g1)
	userPk1 := ed25519.GenPrivKey().PubKey()
	userAddr1 := sdk.AccAddress(userPk1.Address())
	dleProof, _, _, err := elgamal.DLE(suite, g1, g2, x)
	if err != nil {
		t.Errorf("Dle proof don't created")
	}
	decShare := DecryptionShare{g2, dleProof, userAddr1}
	decShareJSON, err := NewDecryptionShareJSON(&decShare)
	if err != nil {
		t.Errorf("failed to json: %v", err)
	}
	decShareJSONBytes, err := ModuleCdc.MarshalJSON(decShareJSON)
	if err != nil {
		t.Errorf("failed marshal: %v", err)
	}
	var bytes *DecryptionShareJSON
	err1 := ModuleCdc.UnmarshalJSON(decShareJSONBytes, &bytes)
	if err1 != nil {
		t.Errorf("failed unmarshal: %v", err1)
	}
	newdecShare, err2 := DeserializeDecryptionShare(bytes)
	if err2 != nil {
		t.Errorf("failed from json: %v", err2)
	}
	if !newdecShare.KeyHolder.Equals(decShare.KeyHolder) {
		t.Errorf("addresses don't equal")
	}
	if !newdecShare.DecShare.Equal(decShare.DecShare) {
		t.Errorf("decryption shares don't equal")
	}
	if !newdecShare.DLEproof.C.Equal(decShare.DLEproof.C) ||
		!newdecShare.DLEproof.R.Equal(decShare.DLEproof.R) ||
		!newdecShare.DLEproof.VG.Equal(decShare.DLEproof.VG) ||
		!newdecShare.DLEproof.VH.Equal(decShare.DLEproof.VH) {
		t.Errorf("dle proofs don't equal")
	}
	return
}
func TestEncodingDecodingPoint(t *testing.T) {
	group := P256
	mult := group.Scalar().SetInt64(3)
	key := group.Point().Mul(mult, nil)
	str, err := kyberenc.PointToStringHex(group, key)
	if err != nil {
		t.Errorf("failed to encode key as string: %v", err)
	}
	fmt.Printf(str)
	newKey, err := kyberenc.StringHexToPoint(group, str)
	if err != nil {
		t.Errorf("failed to decode key: %v", err)
	}
	if !newKey.Equal(key) {
		t.Errorf("keys are not equal")
	}

}
