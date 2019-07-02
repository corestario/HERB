package herb

import (
	"encoding/binary"
	"fmt"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
	"github.com/dgamingfoundation/HERB/x/herb/types"

	"go.dedis.ch/kyber/v3"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// Keeper maintains the link to data storage and exposes methods for the HERB protocol actions
type Keeper struct {
	storeKey sdk.StoreKey
	group    kyber.Group

	cdc *codec.Codec
}

// NewKeeper creates new instances of the HERB Keeper
func NewKeeper(storeKey sdk.StoreKey, cdc *codec.Codec) Keeper {
	return Keeper{
		storeKey: storeKey,
		group:    P256,
		cdc:      cdc,
	}
}

// SetCiphertext store the ciphertext from the entropyProvider to the kv-store
func (k Keeper) SetCiphertext(ctx sdk.Context, round uint64, ctPart *types.CiphertextPart) sdk.Error {
	if ctPart.EntropyProvider.Empty() {
		return sdk.ErrInvalidAddress("Entropy provider can't be empty!")
	}

	store := ctx.KVStore(k.storeKey)
	roundBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(roundBytes, round)
	ctMap := make(map[string]*types.CiphertextPart)
	var err sdk.Error
	if store.Has(roundBytes) {
		ctMapBytes := store.Get(roundBytes)
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
	store.Set(roundBytes, newCtMapBytes)
	return nil
}

// GetAllCiphertexts returns all ciphertext parts for the given round as go-slice
func (k Keeper) GetAllCiphertexts(ctx sdk.Context, round uint64) (map[string]*types.CiphertextPart, sdk.Error) {
	store := ctx.KVStore(k.storeKey)
	roundBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(roundBytes, round)
	if !store.Has(roundBytes) {
		return nil, sdk.ErrUnknownRequest("Unknown round")
	}
	ctMapBytes := store.Get(roundBytes)
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
