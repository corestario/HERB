package cli

import (
	"fmt"
	"strconv"

	"github.com/dgamingfoundation/HERB/x/herb/elgamal"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/context"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/spf13/cobra"

	"github.com/dgamingfoundation/HERB/x/herb/types"
)

// GetQueryCmd returns the cli query commands for this module
func GetQueryCmd(storeKey string, cdc *codec.Codec) *cobra.Command {
	herbQueryCmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      "Querying commands for the herb module",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	herbQueryCmd.AddCommand(client.GetCommands(
		GetCmdAggregatedCiphertext(storeKey, cdc),
		GetCmdAllCiphertexts(storeKey, cdc),
	)...)

	return herbQueryCmd
}

// GetCmdAggregatedCiphertext implements the query aggregated ciphertext command.
func GetCmdAggregatedCiphertext(queryRoute string, cdc *codec.Codec) *cobra.Command {
	return &cobra.Command{
		Use:   "aggregatedCt [round]",
		Args:  cobra.ExactArgs(1),
		Short: "Query aggregated elgamal ciphertext for the given round",
		RunE: func(cmd *cobra.Command, args []string) error {
			cliCtx := context.NewCLIContext().WithCodec(cdc)
			round, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("round %s not a valid uint, please input a valid round", args[0])
			}
			params := types.NewQueryCtParams(round)
			bz, err := cdc.MarshalJSON(params)
			if err != nil {
				return err
			}

			res, _, err := cliCtx.QueryWithData(fmt.Sprintf("custom/%s/%s", queryRoute, types.QueryAggregatedCt), bz)
			if err != nil {
				return err
			}
			var outJSON elgamal.CiphertextJSON
			cdc.MustUnmarshalJSON(res, &outJSON)
			out, err := outJSON.Deserialize()
			if err != nil {
				return err
			}
			fmt.Println(out.String())
			return nil
			//return cliCtx.PrintOutput(outJSON)
		},
	}
}

func GetCmdAllCiphertexts(queryRoute string, cdc *codec.Codec) *cobra.Command {
	return &cobra.Command{
		Use:   "allCt [round]",
		Args:  cobra.ExactArgs(1),
		Short: "Query all elgamal ciphertexts for the given round",
		RunE: func(cmd *cobra.Command, args []string) error {
			cliCtx := context.NewCLIContext().WithCodec(cdc)
			round, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("round %s not a valid uint, please input a valid round", args[0])
			}
			params := types.NewQueryCtParams(round)
			bz, err := cdc.MarshalJSON(params)
			if err != nil {
				return err
			}

			res, _, err := cliCtx.QueryWithData(fmt.Sprintf("custom/%s/%s", queryRoute, types.QueryAllCt), bz)
			if err != nil {
				return err
			}
			outJSON := make(map[string]*elgamal.CiphertextJSON)
			cdc.MustUnmarshalJSON(res, &outJSON)
			out, err := types.CiphertextMapDeserialize(outJSON)
			if err != nil {
				return err
			}
			for _, ct := range out {
				fmt.Println(ct.String())
			}
			return nil
			//return cliCtx.PrintOutput(outJSON)
		},
	}
}
