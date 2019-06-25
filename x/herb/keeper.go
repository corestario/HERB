package herb

import (
	"encoding/binary"

	"github.com/cosmos/cosmos-sdk/codec"
	//"github.com/dgamingfoundation/HERB/x/herb/elgamal"
	"github.com/dgamingfoundation/HERB/x/herb/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// Keeper maintains the link to data storage and exposes methods for the HERB protocol actions
type Keeper struct {
	storeKey sdk.StoreKey

	cdc *codec.Codec
}

// NewKeeper creates new instances of the HERB Keeper
func NewKeeper(storeKey sdk.StoreKey, cdc *codec.Codec) Keeper {
	return Keeper{
		storeKey: storeKey,
		cdc:      cdc,
	}
}

// SetCiphertext store the ciphertext from the entropyProvider to the kv-store
func (k Keeper) SetCiphertext(ctx sdk.Context, round uint64, ct types.CiphertextPart, entropyProvider sdk.AccAddress) sdk.Error {
	if entropyProvider.Empty() {
		return sdk.ErrInvalidAddress("Entropy provider can't be empty!")
	}

	store := ctx.KVStore(k.storeKey)
	bz := make([]byte, 8)
	binary.LittleEndian.PutUint64(bz, round)
	var ctList []types.CiphertextPart
	if store.Has(bz) {
		ctListBytes := store.Get(bz)
		ctList, err := types.CiphertextArrayDeserialize(ctListBytes)
		if err != nil {
			return err
		}
		ctList = append(ctList, ct)
	} else {
		ctList = []types.CiphertextPart{ct}
	}
	if newCtListBytes, err := types.CiphertextArraySerialize(ctList); err != nil {
		return err
	}
	store.Set(bz, newCtListBytes)
	return nil
}
