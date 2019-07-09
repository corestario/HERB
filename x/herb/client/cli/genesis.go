package cli

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cosmos/cosmos-sdk/client/keys"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/server"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/genutil"

	"github.com/dgamingfoundation/HERB/x/herb/types"
	kyberenc "go.dedis.ch/kyber/v3/util/encoding"
)

const flagClientHome   = "home-client"

// SetThresholdsCmd  implements command for setting decryption threhold and ciphertext parts threshold
func SetThresholdsCmd(ctx *server.Context, cdc *codec.Codec) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set-threshold [ciphertext-thr] [decryption-thr]",
		Short: "add number of the key holder accounts to the genesis file",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			thresholdParts, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("n %s not a valid uint, please input a valid number", args[0])
			}

			thresholdDecryption, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("n %s not a valid uint, please input a valid number", args[0])
			}

			config := ctx.Config
			genFile := config.GenesisFile()
			appState, genDoc, err := genutil.GenesisStateFromGenFile(cdc, genFile)
			if err != nil {
				return err
			}
			genesisStateJSON := appState[types.ModuleName]
			var genesisState types.GenesisState
			types.ModuleCdc.MustUnmarshalJSON(genesisStateJSON, &genesisState)
			genesisState.ThresholdParts = thresholdParts
			genesisState.ThresholdDecryption = thresholdDecryption
			newGenesisState := types.ModuleCdc.MustMarshalJSON(genesisState)
			appState[types.ModuleName] = newGenesisState
			appStateJSON, err := cdc.MarshalJSON(appState)
			if err != nil {
				return err
			}

			// export app state
			genDoc.AppState = appStateJSON

			return genutil.ExportGenesisFile(genDoc, genFile)
		},
	}
	return cmd
}

func AddKeyHolderCmd(ctx *server.Context, cdc *codec.Codec) *cobra.Command {
	return &cobra.Command{
		Use: "add-key-holder [address_or_key_name] [id] [verification_key]",
		Short: "add key holder parameters to genesis file",
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args[] string) error {
			addr, err := sdk.AccAddressFromBech32(args[0])
			if err != nil {
				kb, err := keys.NewKeyBaseFromDir(viper.GetString(flagClientHome))
				if err != nil {
					return err
				}

				info, err := kb.Get(args[0])
				if err != nil {
					return err
				}

				addr = info.GetAddress()
			}

			id, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("n %s not a valid uint, please input a valid number", args[1])
			}

			_, err = kyberenc.StringHexToPoint(types.P256, args[2])
			if err != nil {
				return fmt.Errorf("failed to decode verification key: %v", err)
			}

			config := ctx.Config
			genFile := config.GenesisFile()
			appState, genDoc, err := genutil.GenesisStateFromGenFile(cdc, genFile)
			if err != nil {
				return err
			}
			genesisStateJSON := appState[types.ModuleName]
			var genesisState types.GenesisState
			types.ModuleCdc.MustUnmarshalJSON(genesisStateJSON, &genesisState)

			keyHolders := genesisState.KeyHolders
			if _, ok := keyHolders[addr.String()]; ok {
				return fmt.Errorf("cannot add key holder at existing address %v", addr)
			}
			keyHolders[addr.String()] = types.VerificationKeyJSON{KeyHolderID:int(id), VK:args[2]}
			genesisState.KeyHolders = keyHolders

			newGenesisState := types.ModuleCdc.MustMarshalJSON(genesisState)
			appState[types.ModuleName] = newGenesisState
			appStateJSON, err := cdc.MarshalJSON(appState)
			if err != nil {
				return err
			}

			// export app state
			genDoc.AppState = appStateJSON

			return genutil.ExportGenesisFile(genDoc, genFile)
		},
	}
}
