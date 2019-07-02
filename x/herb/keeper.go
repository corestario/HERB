package herb

import (
	"fmt"
	"strconv"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
	"github.com/dgamingfoundation/HERB/x/herb/types"

	"go.dedis.ch/kyber/v3"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	// key prefixes for defining item in the store by round
	keyCiphertextParts  = "keyCt"     //ciphtetextParts for the round
	keyDecryptionShares = "keyDS"     //descryption shares
	keyRandomResult     = "keyResult" // random point as result of the round
	keyStage            = "keyStage"

	//round stages: ciphertext parts collecting, descryption shares collecting, fresh random number
	stageCt        = "ctCollecting"
	stageDS        = "dsCollecting"
	stageCompleted = "completed"
)

// Keeper maintains the link to data storage and exposes methods for the HERB protocol actions
type Keeper struct {
	storeKey sdk.StoreKey
	group    kyber.Group

	currentRound        uint64
	thresholdDecryption uint64
	thresholdParts      uint64

	cdc *codec.Codec
}

// NewKeeper creates new instances of the HERB Keeper
func NewKeeper(storeKey sdk.StoreKey, cdc *codec.Codec) Keeper {
	return Keeper{
		storeKey:            storeKey,
		group:               P256,
		currentRound:        uint64(0),
		thresholdDecryption: 1,
		thresholdParts:      2,
		cdc:                 cdc,
	}
}

// SetCiphertext store the ciphertext from the entropyProvider to the kv-store
func (k Keeper) SetCiphertext(ctx sdk.Context, round uint64, ctPart *types.CiphertextPart) sdk.Error {
	if ctPart.EntropyProvider.Empty() {
		return sdk.ErrInvalidAddress("Entropy provider can't be empty!")
	}

	store := ctx.KVStore(k.storeKey)
	keyBytes := getKeyBytes(round, keyCiphertextParts)
	ctMap := make(map[string]*types.CiphertextPart)
	var err sdk.Error
	if store.Has(keyBytes) {
		ctMapBytes := store.Get(keyBytes)
		var ctMapJSON map[string]*types.CiphertextPartJSON
		err1 := k.cdc.UnmarshalJSON(ctMapBytes, &ctMapJSON)
		if err1 != nil {
			return sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarshal map from the store: %v", err1))
		}
		ctMap, err = types.CiphertextMapDeserialize(ctMapJSON)
		if err != nil {
			return err
		}
	}

	ctMap[ctPart.EntropyProvider.String()] = ctPart
	newCtMapJSON, err := types.CiphertextMapSerialize(ctMap)
	if err != nil {
		return err
	}
	newCtMapBytes, err2 := k.cdc.MarshalJSON(newCtMapJSON)
	if err2 != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't marshal map for the store: %v", err2))
	}
	store.Set(keyBytes, newCtMapBytes)
	return nil
}

// GetAllCiphertexts returns all ciphertext parts for the given round as go-slice
func (k Keeper) GetAllCiphertexts(ctx sdk.Context, round uint64) (map[string]*types.CiphertextPart, sdk.Error) {
	store := ctx.KVStore(k.storeKey)
	keyBytes := getKeyBytes(round, keyCiphertextParts)
	if !store.Has(keyBytes) {
		return nil, sdk.ErrUnknownRequest("Unknown round")
	}
	ctMapBytes := store.Get(keyBytes)
	var ctMapJSON map[string]*types.CiphertextPartJSON
	err1 := k.cdc.UnmarshalJSON(ctMapBytes, &ctMapJSON)
	if err1 != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarshal map from store: %v", err1))
	}
	ctMap, err := types.CiphertextMapDeserialize(ctMapJSON)
	if err != nil {
		return nil, err
	}
	return ctMap, nil
}

// GetAggregatedCiphertext aggregate all sended ciphertext parts in one ciphertext and returns it
func (k Keeper) GetAggregatedCiphertext(ctx sdk.Context, round uint64) (*elgamal.Ciphertext, sdk.Error) {
	allCts, err := k.GetAllCiphertexts(ctx, round)
	if err != nil {
		return nil, err
	}
	ctArray := make([]elgamal.Ciphertext, 0, len(allCts))
	for _, ct := range allCts {
		ctArray = append(ctArray, ct.Ciphertext)
	}
	aggregatedCiphertext := elgamal.AggregateCiphertext(k.group, ctArray)
	return &aggregatedCiphertext, nil
}

func (k Keeper) setStage(ctx sdk.Context, round uint64, stage string) {
	store := ctx.KVStore(k.storeKey)
	keyBytes := getKeyBytes(round, keyStage)
	store.Set(keyBytes, []byte(stage))
}

func getKeyBytes(round uint64, keyPrefix string) []byte {
	roundStr := strconv.FormatUint(round, 10)
	keyStr := roundStr + keyPrefix
	keyBytes := []byte(keyStr)
	return keyBytes
}

func (k Keeper) SetDecryptionShare(ctx sdk.Context, round uint64, ds *types.DecryptionShare) sdk.Error {
	if ds.KeyHolder.Empty() {
		return sdk.ErrInvalidAddress("Key Holder can't be empty!")
	}
	store := ctx.KVStore(k.storeKey)
	keyBytes := getKeyBytes(round, keyDecryptionShares)
	dsMap := make(map[string]*types.DecryptionShare)
	var err sdk.Error
	if store.Has(keyBytes) {
		dsMapBytes := store.Get(keyBytes)
		var dsMapJSON map[string]*types.DecryptionShareJSON
		err1 := k.cdc.UnmarshalJSON(dsMapBytes, &dsMapJSON)
		if err1 != nil {
			return sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarshal map from the store: %v", err1))
		}
		dsMap, err = types.DecryptionSharesMapDeserialize(dsMapJSON)
		if err != nil {
			return err
		}
	}

	dsMap[ds.KeyHolder.String()] = ds
	newDsMapJSON, err := types.DecryptionSharesMapSerialize(dsMap)
	if err != nil {
		return err
	}
	newDsMapBytes, err2 := k.cdc.MarshalJSON(newDsMapJSON)
	if err2 != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't marshal map for the store: %v", err2))
	}
	store.Set(keyBytes, newDsMapBytes)
	return nil
}

func (k Keeper) GetAllDecryptionShares(ctx sdk.Context, round uint64) (map[string]*types.DecryptionShare, sdk.Error) {
	store := ctx.KVStore(k.storeKey)
	keyBytes := getKeyBytes(round, keyDecryptionShares)
	if !store.Has(keyBytes) {
		return nil, sdk.ErrUnknownRequest("Unknown round")
	}
	dsMapBytes := store.Get(keyBytes)
	var dsMapJSON map[string]*types.DecryptionShareJSON
	err1 := k.cdc.UnmarshalJSON(dsMapBytes, &dsMapJSON)
	if err1 != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarshal map from store: %v", err1))
	}
	dsMap, err := types.DecryptionSharesMapDeserialize(dsMapJSON)
	if err != nil {
		return nil, err
	}
	return dsMap, nil
}
