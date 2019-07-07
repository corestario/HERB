package cli

import (
	"fmt"
	"github.com/dgamingfoundation/HERB/x/herb/types"
	"strconv"

	"github.com/spf13/cobra"
	//"github.com/spf13/viper"
	//"github.com/tendermint/tendermint/libs/cli"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/server"
	"github.com/cosmos/cosmos-sdk/x/genutil"
)

// SetKeyHoldersNumberCmd implements command for setting number of the key holders tp the genesis file
func SetKeyHoldersNumberCmd(ctx *server.Context, cdc *codec.Codec,
	defaultNodeHome, defaultClientHome string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set-kh-number [n]",
		Short: "add number of the key holder accounts to the genesis file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			n, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("n %s not a valid uint, please input a valid number", args[0])
			}

			config := ctx.Config
			genFile := config.GenesisFile()
			appState, _, err := genutil.GenesisStateFromGenFile(cdc, genFile)
			if err != nil {
				return err
			}
			genesisStateJSON := appState[types.ModuleName]
			var genesisState types.GenesisState
			types.ModuleCdc.MustUnmarshalJSON(genesisStateJSON, &genesisState)
			genesisState.KeyHoldersNumber = n
			newGenesisState := types.ModuleCdc.MustMarshalJSON(genesisState)
			appState[types.ModuleName] = newGenesisState
			return nil
		},
	}
	return cmd
}
