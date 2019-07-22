package herb

import (
	"errors"
	"github.com/dgamingfoundation/HERB/x/herb/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	abci "github.com/tendermint/tendermint/abci/types"

	kyberenc "go.dedis.ch/kyber/v3/util/encoding"
)

// NewGenesisState creates new instance GenesisState
func NewGenesisState(thresholdParts uint64, thresholdDecryption uint64) GenesisState {
	return GenesisState{
		ThresholdParts:      thresholdParts,
		ThresholdDecryption: thresholdDecryption,
		CommonPublicKey:     P256.Point().String(),
		KeyHolders:          []types.VerificationKeyJSON{},
	}
}

// ValidateGenesis validates the provided herb genesis state to ensure the
// expected invariants holds.
func ValidateGenesis(data GenesisState) error {
	partsThreshold := data.ThresholdParts
	sharesThreshold := data.ThresholdDecryption
	if partsThreshold < 1 {
		return errors.New("theshold for ciphertext parts must be positive")
	}
	if sharesThreshold < 1 {
		return errors.New("theshold for descryption shares must be positive")
	}

	if _, err := kyberenc.StringHexToPoint(types.P256, data.CommonPublicKey); err != nil {
		return err
	}
	for _, keyHolderJSON := range data.KeyHolders {
		if _, err2 := keyHolderJSON.Deserialize(); err2 != nil {
			return errors.New(err2.Error())
		}
	}
	return nil
}

// DefaultGenesisState returns default testing genesis state
func DefaultGenesisState() GenesisState {
	return GenesisState{
		ThresholdParts:      1,
		ThresholdDecryption: 1,
		CommonPublicKey:     P256.Point().String(),
		KeyHolders:          []types.VerificationKeyJSON{},
	}
}

// InitGenesis sets the pool and parameters for the provided keeper.
func InitGenesis(ctx sdk.Context, keeper Keeper, data GenesisState) []abci.ValidatorUpdate {
	keyHolders := data.KeyHolders

	err := keeper.SetVerificationKeys(ctx, keyHolders)
	if err != nil {
		panic(err)
	}

	keeper.SetKeyHoldersNumber(ctx, uint64(len(keyHolders)))
	keeper.SetThreshold(ctx, data.ThresholdParts, data.ThresholdDecryption)
	keeper.SetCommonPublicKey(ctx, data.CommonPublicKey)
	return []abci.ValidatorUpdate{}
}

// ExportGenesis returns a GenesisState for a given context and keeper.
//TO DO: export genesis (need to complete keeper)
func ExportGenesis(ctx sdk.Context, k Keeper) GenesisState {
	return GenesisState{
		ThresholdParts:      1,
		ThresholdDecryption: 1,
		KeyHolders:          []types.VerificationKeyJSON{},
	}
}
