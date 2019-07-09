package herb

import (
	"github.com/dgamingfoundation/HERB/x/herb/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	abci "github.com/tendermint/tendermint/abci/types"
)

// NewGenesisState creates new instance GenesisState
func NewGenesisState(thresholdParts uint64, thresholdDecryption uint64) GenesisState {
	return GenesisState{
			ThresholdParts: thresholdParts,
			ThresholdDecryption: thresholdDecryption,
			KeyHolders: map[string]types.VerificationKeyJSON{},
		}
}

// ValidateGenesis validates the provided herb genesis state to ensure the
// expected invariants holds.
//TO DO
func ValidateGenesis(data GenesisState) error {

	return nil
}

// DefaultGenesisState returns default testing genesis state
func DefaultGenesisState() GenesisState {
	return GenesisState{
		ThresholdParts: 1,
		ThresholdDecryption: 1,
		KeyHolders: map[string]types.VerificationKeyJSON{},
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
	return []abci.ValidatorUpdate{}
}

// ExportGenesis returns a GenesisState for a given context and keeper.
//TO DO: export genesis (need to complete keeper)
func ExportGenesis(ctx sdk.Context, k Keeper) GenesisState {
	//var records CiphertextPartJSON
	return GenesisState{
		ThresholdParts: 1,
		ThresholdDecryption: 1,
		KeyHolders: map[string]types.VerificationKeyJSON{},
	}
}

