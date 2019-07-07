package types

import (
	"bytes"
	"fmt"

	"go.dedis.ch/kyber/v3"
	kyberenc "go.dedis.ch/kyber/v3/util/encoding"

	"github.com/dgamingfoundation/HERB/x/herb/elgamal"

	"go.dedis.ch/kyber/v3/group/nist"
	"go.dedis.ch/kyber/v3/proof/dleq"
	"go.dedis.ch/kyber/v3/share"

	"encoding/base64"
	"encoding/gob"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

var P256 = nist.NewBlakeSHA256P256()

type VerificationKey struct {
	VK        kyber.Point
	KeyHolder uint
}

type VerificationKeyJSON struct {
	VK        string `json:"verification key"`
	KeyHolder uint   `json:"Key Holder"`
}

func NewVerificationKeyJSON(vk *VerificationKey) (*VerificationKeyJSON, sdk.Error) {
	vkJSON, err := kyberenc.PointToStringHex(P256, vk.VK)
	if err != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("failed to encode verification key: %v", err))
	}
	return &VerificationKeyJSON{
		VK:        vkJSON,
		KeyHolder: vk.KeyHolder,
	}, nil
}
func (vkJSON *VerificationKeyJSON) Deserialize() (*VerificationKey, sdk.Error) {
	vk, err := kyberenc.StringHexToPoint(P256, vkJSON.VK)
	if err != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("failed to decode verification key: %v", err))
	}
	return &VerificationKey{
		VK:        vk,
		KeyHolder: vkJSON.KeyHolder,
	}, nil
}
func VerificationKeysMapSerialize(vkMap map[string]*VerificationKey) (map[string]*VerificationKeyJSON, sdk.Error) {
	vkJSONMap := make(map[string]*VerificationKeyJSON)
	var err error
	for addr, vk := range vkMap {
		vkJSONMap[addr], err = NewVerificationKeyJSON(vk)
		if err != nil {
			return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't serialize map: %v", err))
		}
	}
	return vkJSONMap, nil
}

func VerificationKeyMapDeserialize(vkJSONMap map[string]*VerificationKeyJSON) (map[string]*VerificationKey, sdk.Error) {
	vkMap := make(map[string]*VerificationKey)
	var err error
	for addr, vk := range vkJSONMap {
		vkMap[addr], err = vk.Deserialize()
		if err != nil {
			return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't deserialize verification keys map: %v", err))
		}
	}
	return vkMap, nil
}

// CiphertextPart represents ciphertext part and additional information for the first HERB phase.
type CiphertextPart struct {
	Ciphertext      elgamal.Ciphertext
	DLKproof        []byte
	RKProof         []byte
	EntropyProvider sdk.AccAddress
}

type CiphertextPartJSON struct {
	Ciphertext      string         `json:"ciphertext"`
	DLKproof        []byte         `json:"DLK proof"`
	RKProof         []byte         `json:"RK proof"`
	EntropyProvider sdk.AccAddress `json:"entropyprovider"`
}

func NewCiphertextPartJSON(ciphertextPart *CiphertextPart) (*CiphertextPartJSON, sdk.Error) {
	ctBuf := bytes.NewBuffer(nil)
	ctEnc := gob.NewEncoder(ctBuf)
	ctJSON, _ := elgamal.NewCiphertextJSON(&ciphertextPart.Ciphertext)
	if err := ctEnc.Encode(ctJSON); err != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("failed to encode ciphertext: %v", err))
	}
	return &CiphertextPartJSON{
		Ciphertext:      base64.StdEncoding.EncodeToString(ctBuf.Bytes()),
		DLKproof:        ciphertextPart.DLKproof,
		RKProof:         ciphertextPart.RKProof,
		EntropyProvider: ciphertextPart.EntropyProvider,
	}, nil
}

func (ctJSON *CiphertextPartJSON) Deserialize() (*CiphertextPart, sdk.Error) {
	ciphertextJSONBytes, err := base64.StdEncoding.DecodeString(ctJSON.Ciphertext)
	if err != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("failed to base64-decode ciphertextJSON: %v", err))
	}
	ciphertextJSONDec := gob.NewDecoder(bytes.NewBuffer(ciphertextJSONBytes))
	ciphertextjson := elgamal.CiphertextJSON{"", ""}
	if err := ciphertextJSONDec.Decode(&ciphertextjson); err != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("failed to decode ciphertext json : %v", err))
	}
	ciphertext, err := ciphertextjson.Deserialize()
	if err != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("failed to decode ciphertext: %v", err))
	}
	return &CiphertextPart{
		Ciphertext:      *ciphertext,
		DLKproof:        ctJSON.DLKproof,
		RKProof:         ctJSON.RKProof,
		EntropyProvider: ctJSON.EntropyProvider,
	}, nil
}

func CiphertextMapSerialize(ctMap map[string]*CiphertextPart) (map[string]*CiphertextPartJSON, sdk.Error) {
	ctJSONMap := make(map[string]*CiphertextPartJSON)
	var err error
	for addr, ct := range ctMap {
		ctJSONMap[addr], err = NewCiphertextPartJSON(ct)
		if err != nil {
			return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't serialize map: %v", err))
		}
	}
	return ctJSONMap, nil
}

func CiphertextMapDeserialize(ctJSONMap map[string]*CiphertextPartJSON) (map[string]*CiphertextPart, sdk.Error) {
	ctMap := make(map[string]*CiphertextPart)
	var err error
	for addr, ct := range ctJSONMap {
		ctMap[addr], err = ct.Deserialize()
		if err != nil {
			return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't deserialize ciphertext map: %v", err))
		}
	}
	return ctMap, nil
}

type DecryptionShare struct {
	DecShare  share.PubShare
	DLEproof  *dleq.Proof
	KeyHolder sdk.AccAddress
}
type DecryptionShareJSON struct {
	DecShare  string         `json:"decryptionShare"`
	DLEproof  string         `json:"DLE proof"`
	KeyHolder sdk.AccAddress `json:"keyholder"`
}

func NewDecryptionShareJSON(decShares *DecryptionShare) (*DecryptionShareJSON, sdk.Error) {
	dsBuf := bytes.NewBuffer(nil)
	dsEnc := gob.NewEncoder(dsBuf)
	if err := dsEnc.Encode(decShares.DecShare); err != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("failed to encode decryption shares: %v", err))
	}
	dleBuf := bytes.NewBuffer(nil)
	dleEnc := gob.NewEncoder(dleBuf)
	if err := dleEnc.Encode(decShares.DLEproof); err != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("failed to encode dle proof: %v", err))
	}
	return &DecryptionShareJSON{
		DecShare:  base64.StdEncoding.EncodeToString(dsBuf.Bytes()),
		DLEproof:  base64.StdEncoding.EncodeToString(dleBuf.Bytes()),
		KeyHolder: decShares.KeyHolder,
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
	dleproof := dleq.Proof{P256.Scalar().Zero(), P256.Scalar().Zero(), P256.Point().Base(), P256.Point().Base()}
	if err := dleDec.Decode(&dleproof); err != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("failed to decode DLE proof : %v", err))
	}
	return &DecryptionShare{
		DecShare:  decshare,
		DLEproof:  &dleproof,
		KeyHolder: dsJSON.KeyHolder,
	}, nil
}
func DecryptionSharesMapSerialize(dsMap map[string]*DecryptionShare) (map[string]*DecryptionShareJSON, sdk.Error) {
	dsJSONMap := make(map[string]*DecryptionShareJSON)
	var err error
	for addr, ds := range dsMap {
		dsJSONMap[addr], err = NewDecryptionShareJSON(ds)
		if err != nil {
			return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't serialize map: %v", err))
		}
	}
	return dsJSONMap, nil
}

func DecryptionSharesMapDeserialize(dsJSONMap map[string]*DecryptionShareJSON) (map[string]*DecryptionShare, sdk.Error) {
	dsMap := make(map[string]*DecryptionShare)
	var err error
	for addr, ds := range dsJSONMap {
		dsMap[addr], err = ds.Deserialize()
		if err != nil {
			return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't deserialize  map: %v", err))
		}
	}
	return dsMap, nil
}
