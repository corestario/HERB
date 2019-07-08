package herb

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
	abci "github.com/tendermint/tendermint/abci/types"
)

// NewGenesisState creates new instance GenesisState
func NewGenesisState(ciphertextPartRecords []CiphertextPartJSON, keyHoldersNum uint64) GenesisState {
	return GenesisState{CiphertextPartRecords: nil, KeyHoldersNumber: keyHoldersNum}
}

// ValidateGenesis validates the provided herb genesis state to ensure the
// expected invariants holds.
func ValidateGenesis(data GenesisState) error {
	for _, record := range data.CiphertextPartRecords {
		if record.EntropyProvider.Empty() {
			return fmt.Errorf("Invalid ciphertext part: Ciphertext: %s. Error: Missing Entropy Provider", record.Ciphertext)
		}
		_, err := record.Deserialize()
		if err != nil {
			return err
		}
	}
	return nil
}

// DefaultGenesisState returns default testing genesis state
func DefaultGenesisState() GenesisState {
	return GenesisState{
		CiphertextPartRecords: []CiphertextPartJSON{},
	}
}

// InitGenesis sets the pool and parameters for the provided keeper.
func InitGenesis(ctx sdk.Context, keeper Keeper, data GenesisState) []abci.ValidatorUpdate {
	for _, record := range data.CiphertextPartRecords {
		ct, _ := record.Deserialize()
		keeper.SetCiphertext(ctx, ct)
	}
	keeper.SetKeyHoldersNumber(ctx, data.KeyHoldersNumber)
	return []abci.ValidatorUpdate{}
}

// ExportGenesis returns a GenesisState for a given context and keeper.
//TO DO: export genesis (need to complete keeper)
func ExportGenesis(ctx sdk.Context, k Keeper) GenesisState {
	//var records CiphertextPartJSON
	return GenesisState{
		CiphertextPartRecords: []CiphertextPartJSON{},
	}
}

