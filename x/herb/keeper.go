package herb

import (
	"encoding/binary"
	"go.dedis.ch/kyber/v3"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
	"github.com/dgamingfoundation/HERB/x/herb/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// Keeper maintains the link to data storage and exposes methods for the HERB protocol actions
type Keeper struct {
	storeKey sdk.StoreKey
	group kyber.Group

	cdc *codec.Codec
}

// NewKeeper creates new instances of the HERB Keeper
func NewKeeper(storeKey sdk.StoreKey, group kyber.Group, cdc *codec.Codec) Keeper {
	return Keeper{
		storeKey: storeKey,
		group: group,
		cdc:      cdc,
	}
}

// SetCiphertext store the ciphertext from the entropyProvider to the kv-store
func (k Keeper) SetCiphertext(ctx sdk.Context, round uint64, ct types.CiphertextPart, entropyProvider sdk.AccAddress) sdk.Error {
	if entropyProvider.Empty() {
		return sdk.ErrInvalidAddress("Entropy provider can't be empty!")
	}

	store := ctx.KVStore(k.storeKey)
	key := make([]byte, 8)
	binary.LittleEndian.PutUint64(key, round)
	var ctList []types.CiphertextPart
	if store.Has(key) {
		ctListBytes := store.Get(key)
		ctList, err := types.CiphertextArrayDeserialize(ctListBytes)
		if err != nil {
			return err
		}
		ctList = append(ctList, ct)
	} else {
		ctList = []types.CiphertextPart{ct}
	}
	newCtListBytes, err := types.CiphertextArraySerialize(ctList)
	if err != nil {
		return err
	}
	store.Set(key, newCtListBytes)
	return nil
}

// GetAllCiphertext returns all ciphertext parts for the given round
func (k Keeper) GetAllCiphertext(ctx sdk.Context, round uint64) ([]types.CiphertextPart, sdk.Error) {
	store := ctx.KVStore(k.storeKey)
	key := make([]byte, 8)
	binary.LittleEndian.PutUint64(key, round)
	if !store.Has(key) {
		return nil, sdk.ErrUnknownRequest("Unknown round")
	}
	ctListBytes := store.Get(key)
	ctList, err := types.CiphertextArrayDeserialize(ctListBytes)
	if err != nil {
		return nil, err
	}
	return ctList, nil
}

// GetAggregatedCiphertext aggregate all sended ciphertext parts in one ciphertext and returns it
func (k Keeper) GetAggregatedCiphertext(ctx sdk.Context, round uint64) (*elgamal.Ciphertext, sdk.Error) {
	allParts, err := k.GetAllCiphertext(ctx, round)
	if err != nil {
		return nil, err
	}
	ctArray := make([]elgamal.Ciphertext, len(allParts))
	aggregatedCiphertext := elgamal.AggregateCiphertext(k.group, ctArray)
	return &aggregatedCiphertext, nil
}
