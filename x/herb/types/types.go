package types

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/nist"
	"go.dedis.ch/kyber/v3/proof/dleq"
	"go.dedis.ch/kyber/v3/share"
	kyberenc "go.dedis.ch/kyber/v3/util/encoding"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
)

var P256 = nist.NewBlakeSHA256P256()

// GenesisState - herb genesis state
type GenesisState struct {
	ThresholdParts      uint64                `json:"threshold_parts"`
	ThresholdDecryption uint64                `json:"threshold_decryption"`
	CommonPublicKey     string                `json:"common_public_key"`
	KeyHolders          []VerificationKeyJSON `json:"key_holders"`
}

type VerificationKey struct {
	Key         kyber.Point
	KeyHolderID int
	Sender      sdk.AccAddress
}

type VerificationKeyJSON struct {
	Key         string         `json:"verification_key"`
	KeyHolderID int            `json:"key_holder_id"`
	Sender      sdk.AccAddress `json:"sender_address"`
}

func NewVerificationKeyJSON(vk *VerificationKey) (VerificationKeyJSON, sdk.Error) {
	vkJSON, err := kyberenc.PointToStringHex(P256, vk.Key)
	if err != nil {
		return VerificationKeyJSON{}, sdk.ErrUnknownRequest(fmt.Sprintf("failed to encode verification key: %v", err))
	}
	return VerificationKeyJSON{
		Key:         vkJSON,
		KeyHolderID: vk.KeyHolderID,
		Sender:      vk.Sender,
	}, nil
}
func (vkJSON VerificationKeyJSON) Deserialize() (*VerificationKey, sdk.Error) {
	vk, err := kyberenc.StringHexToPoint(P256, vkJSON.Key)
	if err != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("failed to decode verification key: %v", err))
	}
	return &VerificationKey{
		Key:         vk,
		KeyHolderID: vkJSON.KeyHolderID,
		Sender:      vkJSON.Sender,
	}, nil
}

// CiphertextPart represents ciphertext part and additional information for the first HERB phase.
type CiphertextPart struct {
	Ciphertext      elgamal.Ciphertext
	DLKproof        []byte
	RKproof         []byte
	EntropyProvider sdk.AccAddress
}

type CiphertextPartJSON struct {
	Ciphertext      elgamal.CiphertextJSON `json:"ciphertext"`
	DLKproof        []byte                 `json:"dlk_proof"`
	RKproof         []byte                 `json:"rk_proof"`
	EntropyProvider sdk.AccAddress         `json:"entropy_provider"`
}

func NewCiphertextPartJSON(ciphertextPart *CiphertextPart) (*CiphertextPartJSON, sdk.Error) {
	ctJSON, _ := elgamal.NewCiphertextJSON(&ciphertextPart.Ciphertext, P256)

	return &CiphertextPartJSON{
		Ciphertext:      *ctJSON,
		DLKproof:        ciphertextPart.DLKproof,
		RKproof:         ciphertextPart.RKproof,
		EntropyProvider: ciphertextPart.EntropyProvider,
	}, nil
}

func (ctJSON *CiphertextPartJSON) Deserialize() (*CiphertextPart, sdk.Error) {
	ciphertext, err := ctJSON.Ciphertext.Deserialize(P256)
	if err != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("failed to decode ciphertext: %v", err))
	}
	return &CiphertextPart{
		Ciphertext:      *ciphertext,
		DLKproof:        ctJSON.DLKproof,
		RKproof:         ctJSON.RKproof,
		EntropyProvider: ctJSON.EntropyProvider,
	}, nil
}

type DecryptionShare struct {
	DecShare      share.PubShare
	DLEproof      *dleq.Proof
	KeyHolderAddr sdk.AccAddress
}
type DecryptionShareJSON struct {
	DecShare      string         `json:"decryption_share"`
	DLEproof      string         `json:"dle_proof"`
	KeyHolderAddr sdk.AccAddress `json:"key_holder"`
}

func NewDecryptionShareJSON(decShares *DecryptionShare) (DecryptionShareJSON, sdk.Error) {
	dsBuf := bytes.NewBuffer(nil)
	dsEnc := gob.NewEncoder(dsBuf)
	if err := dsEnc.Encode(decShares.DecShare); err != nil {
		return DecryptionShareJSON{}, sdk.ErrUnknownRequest(fmt.Sprintf("failed to encode decryption shares: %v", err))
	}
	dleBuf := bytes.NewBuffer(nil)
	dleEnc := gob.NewEncoder(dleBuf)
	if err := dleEnc.Encode(decShares.DLEproof); err != nil {
		return DecryptionShareJSON{}, sdk.ErrUnknownRequest(fmt.Sprintf("failed to encode dle proof: %v", err))
	}
	return DecryptionShareJSON{
		DecShare:      base64.StdEncoding.EncodeToString(dsBuf.Bytes()),
		DLEproof:      base64.StdEncoding.EncodeToString(dleBuf.Bytes()),
		KeyHolderAddr: decShares.KeyHolderAddr,
	}, nil
}
func (dsJSON DecryptionShareJSON) Deserialize() (*DecryptionShare, sdk.Error) {
	dsBytes, err := base64.StdEncoding.DecodeString(dsJSON.DecShare)
	if err != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("failed to base64-decode decryption shares: %v", err))
	}
	dsDec := gob.NewDecoder(bytes.NewBuffer(dsBytes))
	decshare := share.PubShare{I: 0, V: P256.Point().Base()}
	if err := dsDec.Decode(&decshare); err != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("failed to decode decryption share : %v", err))
	}

	dleBytes, err := base64.StdEncoding.DecodeString(dsJSON.DLEproof)
	if err != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("failed to base64-decode DLE proof: %v", err))
	}
	dleDec := gob.NewDecoder(bytes.NewBuffer(dleBytes))
	dleproof := dleq.Proof{C: P256.Scalar().Zero(), R: P256.Scalar().Zero(), VG: P256.Point().Base(), VH: P256.Point().Base()}
	if err := dleDec.Decode(&dleproof); err != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("failed to decode DLE proof : %v", err))
	}
	return &DecryptionShare{
		DecShare:      decshare,
		DLEproof:      &dleproof,
		KeyHolderAddr: dsJSON.KeyHolderAddr,
	}, nil
}

func CiphertextArraySerialize(ctArray []*CiphertextPart) ([]*CiphertextPartJSON, sdk.Error) {
	ctJSONArray := make([]*CiphertextPartJSON, 0)
	for _, ct := range ctArray {
		pt, err := NewCiphertextPartJSON(ct)
		if err != nil {
			return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't serialize array: %v", err))
		}
		ctJSONArray = append(ctJSONArray, pt)
	}
	return ctJSONArray, nil
}
func CiphertextArrayDeserialize(ctJSONArray []*CiphertextPartJSON) ([]*CiphertextPart, sdk.Error) {
	ctArray := make([]*CiphertextPart, 0)
	for _, ct := range ctJSONArray {
		ct := ct
		pt, err := ct.Deserialize()
		if err != nil {
			return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't deserialize array: %v", err))
		}
		ctArray = append(ctArray, pt)
	}
	return ctArray, nil
}

func DecryptionSharesArraySerialize(dsArray []*DecryptionShare) ([]DecryptionShareJSON, sdk.Error) {
	dsJSONArray := make([]DecryptionShareJSON, len(dsArray))
	var err sdk.Error
	for i, ds := range dsArray {
		dsJSONArray[i], err = NewDecryptionShareJSON(ds)
		if err != nil {
			return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't serialize array: %v", err))
		}
	}
	return dsJSONArray, nil
}
func DecryptionSharesArrayDeserialize(dsJSONArray []*DecryptionShareJSON) ([]*DecryptionShare, sdk.Error) {
	dsArray := make([]*DecryptionShare, len(dsJSONArray))
	var err sdk.Error
	for i, ds := range dsJSONArray {
		dsArray[i], err = ds.Deserialize()
		if err != nil {
			return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't deserialize array: %v", err))
		}
	}
	return dsArray, nil
}

func VerificationKeyArraySerialize(vkList []*VerificationKey) ([]VerificationKeyJSON, sdk.Error) {
	vkJSONList := make([]VerificationKeyJSON, len(vkList))
	var err error
	for i, vk := range vkList {
		vkJSONList[i], err = NewVerificationKeyJSON(vk)
		if err != nil {
			return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't serialize array: %v", err))
		}
	}
	return vkJSONList, nil
}

func VerificationKeyArrayDeserialize(vkJSONList []VerificationKeyJSON) ([]*VerificationKey, sdk.Error) {
	vkList := make([]*VerificationKey, len(vkJSONList))
	var err error
	for i, vk := range vkJSONList {
		vkList[i], err = vk.Deserialize()
		if err != nil {
			return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't deserialize verification keys array: %v", err))
		}
	}
	return vkList, nil
}
