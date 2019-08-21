package types

import (
	"fmt"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
	"github.com/tendermint/tendermint/crypto/ed25519"

	"go.dedis.ch/kyber/v3/group/nist"
	"go.dedis.ch/kyber/v3/share"
	kyberenc "go.dedis.ch/kyber/v3/util/encoding"
)

func TestCiphertextSerialization(t *testing.T) {
	suite := nist.NewBlakeSHA256P256()
	g1 := suite.Point().Base()
	g2 := suite.Point().Mul(suite.Scalar().SetInt64(2), g1)
	ct := elgamal.Ciphertext{PointA: g1, PointB: g2}
	userPk1 := ed25519.GenPrivKey().PubKey()
	userAddr1 := sdk.AccAddress(userPk1.Address())
	ctPart := CiphertextPart{ct, []byte("example"), []byte("example3"), userAddr1}
	ctPartJSON, err := NewCiphertextPartJSON(&ctPart)
	if err != nil {
		t.Errorf("failed to json: %v", err)
	}
	ctPartBytes, err1 := ModuleCdc.MarshalJSON(ctPartJSON)
	if err1 != nil {
		t.Errorf("failed marshal: %v", err1)
	}
	var newctPartJSON CiphertextPartJSON
	err1 = ModuleCdc.UnmarshalJSON(ctPartBytes, &newctPartJSON)
	if err1 != nil {
		t.Errorf("failed unmarshal: %v", err1)
	}
	newctPart, err := newctPartJSON.Deserialize()
	if err != nil {
		t.Errorf("failed to json: %v", err)
	}
	if !ctPart.EntropyProvider.Equals(newctPart.EntropyProvider) {
		t.Errorf("addresses are not equal")
	}
	if !ctPart.Ciphertext.Equal(newctPart.Ciphertext) {
		t.Errorf("ciphertexts are not equal")
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
		t.Errorf("can't create dle proof")
	}
	decShare := DecryptionShare{share.PubShare{I: 0, V: g2}, dleProof, userAddr1}
	decShareJSON, err1 := NewDecryptionShareJSON(&decShare)
	if err1 != nil {
		t.Errorf("failed to json: %v", err1)
	}
	decShareJSONBytes, err := ModuleCdc.MarshalJSON(decShareJSON)
	if err != nil {
		t.Errorf("failed marshal: %v", err)
	}
	var bytes *DecryptionShareJSON
	err = ModuleCdc.UnmarshalJSON(decShareJSONBytes, &bytes)
	if err != nil {
		t.Errorf("failed unmarshal: %v", err)
	}
	newdecShare, err1 := bytes.Deserialize()
	if err1 != nil {
		t.Errorf("failed from json: %v", err1)
	}
	if !newdecShare.KeyHolderAddr.Equals(decShare.KeyHolderAddr) {
		t.Errorf("addresses are not equal")
	}
	if !newdecShare.DecShare.V.Equal(decShare.DecShare.V) {
		t.Errorf("decryption shares are not equal")
	}
	if !newdecShare.DLEproof.C.Equal(decShare.DLEproof.C) ||
		!newdecShare.DLEproof.R.Equal(decShare.DLEproof.R) ||
		!newdecShare.DLEproof.VG.Equal(decShare.DLEproof.VG) ||
		!newdecShare.DLEproof.VH.Equal(decShare.DLEproof.VH) {
		t.Errorf("dle proofs are not equal")
	}
	return
}
func TestEncodingDecodingPoint(t *testing.T) {
	group := P256
	mult := group.Scalar().SetInt64(3)
	key := group.Point().Mul(mult, nil)
	str, err := kyberenc.PointToStringHex(group, key)
	if err != nil {
		t.Errorf("failed to encode key as a string: %v", err)
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
