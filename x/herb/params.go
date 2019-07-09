package herb

import (
	"encoding/binary"
	"github.com/dgamingfoundation/HERB/x/herb/types"
	"go.dedis.ch/kyber/v3"
	kyberenc "go.dedis.ch/kyber/v3/util/encoding"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

//this file defines HERB parameters (such as threshold, participants ID's etc.) functions

// SetKeyHoldersNumber set the number of key holders (n for (t, n)-threshold cryptosystem)
func (k *Keeper) SetKeyHoldersNumber(ctx sdk.Context, n uint64) {
	store := ctx.KVStore(k.storeKey)
	nBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(nBytes, n)
	store.Set([]byte(keyKeyHoldersNumber), nBytes)
}

// GetKeyHoldersNumber returns size of the current key holders group
func (k *Keeper) GetKeyHoldersNumber(ctx sdk.Context) (uint64, sdk.Error) {
	store := ctx.KVStore(k.storeKey)
	if !store.Has([]byte(keyKeyHoldersNumber)) {
		return 0, sdk.ErrUnknownRequest("Store doesn't contain number of key holders")
	}
	nBytes := store.Get([]byte(keyKeyHoldersNumber))
	n := binary.LittleEndian.Uint64(nBytes)
	return n, nil
}

// SetVerificationKeys set verification keys corresponding to each address
func (k *Keeper) SetVerificationKeys(ctx sdk.Context, verificationKeys map[string]types.VerificationKeyJSON) sdk.Error {
	store := ctx.KVStore(k.storeKey)
	if store.Has([]byte(keyVerificationKeys)) {
		return sdk.ErrUnknownRequest("Verification keys already exist")
	}

	verificationKeysBytes, err := k.cdc.MarshalJSON(verificationKeys)
	if err != nil {
		return sdk.ErrUnknownRequest("Can't marshal map")
	}

	store.Set([]byte(keyVerificationKeys), verificationKeysBytes)
	return nil
}

// GetVerificationKeys returns verification keys corresponding to each address
func (k *Keeper) GetVerificationKeys(ctx sdk.Context) (map[string]types.VerificationKeyJSON, sdk.Error) {
	store := ctx.KVStore(k.storeKey)
	if !store.Has([]byte(keyVerificationKeys)) {
		return nil, sdk.ErrUnknownRequest("Verification keys are not defined")
	}
	verificationKeysBytes := store.Get([]byte(keyVerificationKeys))
	verificationKeys := make(map[string]types.VerificationKeyJSON)
	k.cdc.MustUnmarshalJSON(verificationKeysBytes, &verificationKeys)
	return verificationKeys, nil
}

// SetThreshold set threshold for decryption and ciphertext parts
func (k *Keeper) SetThreshold(ctx sdk.Context, thresholdParts uint64, thresholdDecrypt uint64) {
	store := ctx.KVStore(k.storeKey)
	thresholdPartsBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(thresholdPartsBytes, thresholdParts)
	store.Set([]byte(keyThresholdParts), thresholdPartsBytes)
	thresholdDecryptBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(thresholdDecryptBytes, thresholdDecrypt)
	store.Set([]byte(keyThresholdDecrypt), thresholdDecryptBytes)
}

func (k *Keeper) GetThresholdParts(ctx sdk.Context) (uint64, sdk.Error) {
	store := ctx.KVStore(k.storeKey)
	if !store.Has([]byte(keyThresholdParts)) {
		return 0, sdk.ErrUnknownRequest("Threshold for ciphertext parts is not defined")
	}

	tBytes := store.Get([]byte(keyThresholdParts))
	t := binary.LittleEndian.Uint64(tBytes)
	return t, nil
}

func (k *Keeper) GetThresholdDecryption(ctx sdk.Context) (uint64, sdk.Error) {
	store := ctx.KVStore(k.storeKey)
	if !store.Has([]byte(keyThresholdDecrypt)) {
		return 0, sdk.ErrUnknownRequest("Decryption threshold is not defined")
	}

	tBytes := store.Get([]byte(keyThresholdDecrypt))
	t := binary.LittleEndian.Uint64(tBytes)
	return t, nil
}

func (k *Keeper) SetCommonPublicKey(ctx sdk.Context, pubKeyHex string) {
	store := ctx.KVStore(k.storeKey)
	keyBytes := []byte(pubKeyHex)
	store.Set([]byte(keyCommonKey), keyBytes)
}

func (k *Keeper) GetCommonPublicKey(ctx sdk.Context) (kyber.Point, sdk.Error) {
	store := ctx.KVStore(k.storeKey)
	keyBytes := store.Get([]byte(keyCommonKey))
	key, err := kyberenc.StringHexToPoint(P256, string(keyBytes))
	if err != nil {
		return nil, sdk.ErrUnknownRequest("Common key is not defined")
	}
	return key, nil
}