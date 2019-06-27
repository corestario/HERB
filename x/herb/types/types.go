package types

import (
	"bytes"
	"fmt"

	"github.com/dgamingfoundation/HERB/x/herb/elgamal"

	"encoding/base64"
	"encoding/gob"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// CiphertextPart represents ciphertext part and additional information for the first HERB phase.
type CiphertextPart struct {
	Ciphertext      elgamal.Ciphertext
	EntropyProvider sdk.AccAddress
}

type CiphertextPartJSON struct {
	Ciphertext      string         `json:"ciphertext"`
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
		EntropyProvider: ctJSON.EntropyProvider,
	}, nil
}

func CiphertextArraySerialize(ctArray []*CiphertextPart) ([]*CiphertextPartJSON, sdk.Error) {
	ctJSONArray := make([]*CiphertextPartJSON, len(ctArray))
	var err sdk.Error
	for i, ct := range ctArray {
		ctJSONArray[i], err = NewCiphertextPartJSON(ct)
		if err != nil {
			return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't serialize array: %v", err))
		}
	}
	return ctJSONArray, nil
}

func CiphertextArrayDeserialize(ctJSONArray []*CiphertextPartJSON) ([]*CiphertextPart, sdk.Error) {
	ctArray := make([]*CiphertextPart, len(ctJSONArray))
	var err sdk.Error
	for i, ct := range ctJSONArray {
		ctArray[i], err = ct.Deserialize()
		if err != nil {
			return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't deserialize array: %v", err))
		}
	}
	return ctArray, nil
}
