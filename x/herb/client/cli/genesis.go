package cli

import (
	"fmt"
	"strconv"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/server"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/genutil"

	"github.com/spf13/cobra"

	"github.com/dgamingfoundation/HERB/x/herb/types"
	kyberenc "go.dedis.ch/kyber/v3/util/encoding"
)

// SetThresholdsCmd  implements command for setting decryption threhold and ciphertext parts threshold
func SetThresholdsCmd(ctx *server.Context, cdc *codec.Codec) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set-threshold [ciphertext-thr] [decryption-thr]",
		Short: "add number of the key holder accounts to the genesis file",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			thresholdParts, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("ciphertext-thr %s not a valid uint, please input a valid number", args[0])
			}

			thresholdDecryption, err := strconv.ParseUint(args[1], 10, 64)
			if err != nil {
				return fmt.Errorf("decryption-thr %s not a valid uint, please input a valid number", args[0])
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

// AddKeyHolderCmd  implements command for setting key holder's id and verification key
func AddKeyHolderCmd(ctx *server.Context, cdc *codec.Codec) *cobra.Command {
	return &cobra.Command{
		Use:   "add-key-holder [address] [id] [verification_key]",
		Short: "add key holder parameters to genesis file",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			config := ctx.Config

			addr, err := sdk.AccAddressFromBech32(args[0])
			if err != nil {
				return err
			}

			id, err := strconv.ParseUint(args[1], 10, 64)
			if err != nil {
				return fmt.Errorf("id %s not a valid uint, please input a valid number", args[1])
			}

			_, err = kyberenc.StringHexToPoint(types.P256, args[2])
			if err != nil {
				return fmt.Errorf("failed to decode verification key: %v", err)
			}

			genFile := config.GenesisFile()
			appState, genDoc, err := genutil.GenesisStateFromGenFile(cdc, genFile)
			if err != nil {
				return err
			}
			genesisStateJSON := appState[types.ModuleName]
			var genesisState types.GenesisState
			types.ModuleCdc.MustUnmarshalJSON(genesisStateJSON, &genesisState)

			keyHolders := genesisState.KeyHolders
			for _, kh := range keyHolders {
				if kh.Sender.Equals(addr) {
					return fmt.Errorf("cannot add key holder at existing address %v", addr)
				}
			}

			keyHolders = append(keyHolders, types.VerificationKeyJSON{KeyHolderID: int(id), Key: args[2], Sender: addr})
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

// SetCommonPublicKeyCmd implements command for setting common key given in a hexidecimal representation
func SetCommonPublicKeyCmd(ctx *server.Context, cdc *codec.Codec) *cobra.Command {
	return &cobra.Command{
		Use:   "set-common-key [keyHex]",
		Short: "Set common public key for ElGamal cryptosystem",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			if _, err := kyberenc.StringHexToPoint(types.P256, args[0]); err != nil {
				return fmt.Errorf("common key %s not a valid kyber point, please input a valid point", args[0])
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
			genesisState.CommonPublicKey = args[0]
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
