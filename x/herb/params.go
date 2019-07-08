package herb

import (
	"encoding/binary"

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
