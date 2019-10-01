package cli

import (
	"fmt"
	"strconv"

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
		GetCmdAllDecryptionShares(storeKey, cdc),
		GetCmdCurrentRound(storeKey, cdc),
		GetCmdRoundStage(storeKey, cdc),
		GetCmdRoundResult(storeKey, cdc),
	)...)

	return herbQueryCmd
}

// GetCmdAggregatedCiphertext implements the query aggregated ciphertext command.
func GetCmdAggregatedCiphertext(queryRoute string, cdc *codec.Codec) *cobra.Command {
	return &cobra.Command{
		Use:   "aggregated-ct [round](optional)",
		Args:  cobra.MaximumNArgs(1),
		Short: "Query aggregated elgamal ciphertext for the given round",
		RunE: func(cmd *cobra.Command, args []string) error {
			cliCtx := context.NewCLIContext().WithCodec(cdc)

			var round int64
			if len(args) > 0 {
				parsedRound, err := strconv.ParseUint(args[0], 10, 64)
				if err != nil {
					return fmt.Errorf("round %s not a valid uint, please input a valid round", args[0])
				}
				round = int64(parsedRound)
			} else {
				round = -1
			}

			params := types.NewQueryByRound(round)
			bz, err := cdc.MarshalJSON(params)
			if err != nil {
				return err
			}

			res, _, err := cliCtx.QueryWithData(fmt.Sprintf("custom/%s/%s", queryRoute, types.QueryAggregatedCt), bz)
			if err != nil {
				return err
			}
			var out types.QueryAggregatedCtRes
			cdc.MustUnmarshalJSON(res, &out)

			fmt.Println(out.String())
			return nil
		},
	}
}

// GetCmdAllCiphertexts implements the query of all ciphertexts command.
func GetCmdAllCiphertexts(queryRoute string, cdc *codec.Codec) *cobra.Command {
	return &cobra.Command{
		Use:   "all-ct [round](optional)",
		Args:  cobra.MaximumNArgs(1),
		Short: "Query all elgamal ciphertexts for the given round",
		RunE: func(cmd *cobra.Command, args []string) error {
			cliCtx := context.NewCLIContext().WithCodec(cdc)

			var round int64
			if len(args) > 0 {
				parsedRound, err := strconv.ParseUint(args[0], 10, 64)
				if err != nil {
					return fmt.Errorf("round %s not a valid uint, please input a valid round", args[0])
				}
				round = int64(parsedRound)
			} else {
				round = -1
			}

			params := types.NewQueryByRound(round)
			bz, err := cdc.MarshalJSON(params)
			if err != nil {
				return err
			}

			res, _, err := cliCtx.QueryWithData(fmt.Sprintf("custom/%s/%s", queryRoute, types.QueryAllCt), bz)
			if err != nil {
				return err
			}
			var out types.QueryAllCtRes
			cdc.MustUnmarshalJSON(res, &out)

			fmt.Printf(out.String())

			return nil
		},
	}
}

// GetCmdAllDecryptionShares implements the query of all decryption shares command.
func GetCmdAllDecryptionShares(queryRoute string, cdc *codec.Codec) *cobra.Command {
	return &cobra.Command{
		Use:   "all-shares [round](optional)",
		Short: "Queries all decryption shares for the given round",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cliCtx := context.NewCLIContext().WithCodec(cdc)

			var round int64
			if len(args) > 0 {
				parsedRound, err := strconv.ParseUint(args[0], 10, 64)
				if err != nil {
					return fmt.Errorf("round %s not a valid uint, please input a valid round", args[0])
				}
				round = int64(parsedRound)
			} else {
				round = -1
			}

			params := types.NewQueryByRound(round)
			bz, err := cdc.MarshalJSON(params)
			if err != nil {
				return err
			}

			res, _, err := cliCtx.QueryWithData(fmt.Sprintf("custom/%s/%s", queryRoute, types.QueryAllDescryptionShares), bz)
			if err != nil {
				return err
			}

			var out types.QueryAllDescryptionSharesRes
			cdc.MustUnmarshalJSON(res, &out)

			if err != nil {
				return err
			}

			fmt.Printf(out.String())

			return nil
		},
	}
}

func GetCmdCurrentRound(queryRoute string, cdc *codec.Codec) *cobra.Command {
	return &cobra.Command{
		Use:   "current-round",
		Short: "returns current generation round",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cliCtx := context.NewCLIContext().WithCodec(cdc)

			resBytes, _, err := cliCtx.QueryWithData(fmt.Sprintf("custom/%s/%s", queryRoute, types.QueryCurrentRound), nil)
			if err != nil {
				return err
			}

			var out types.QueryCurrentRoundRes
			cdc.MustUnmarshalJSON(resBytes, &out)

			fmt.Println(out.Round)

			return nil
		},
	}
}

func GetCmdRoundStage(queryRoute string, cdc *codec.Codec) *cobra.Command {
	return &cobra.Command{
		Use:   "stage [round](optional)",
		Short: "returns rounds stage",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cliCtx := context.NewCLIContext().WithCodec(cdc)

			var round int64
			if len(args) > 0 {
				parsedRound, err := strconv.ParseUint(args[0], 10, 64)
				if err != nil {
					return fmt.Errorf("round %s not a valid uint, please input a valid round", args[0])
				}
				round = int64(parsedRound)
			} else {
				round = -1
			}

			params := types.NewQueryByRound(round)
			bz, err := cdc.MarshalJSON(params)
			if err != nil {
				return err
			}

			stageBytes, _, err := cliCtx.QueryWithData(fmt.Sprintf("custom/%s/%s", queryRoute, types.QueryStage), bz)
			if err != nil {
				return err
			}

			var out types.QueryStageRes
			cdc.MustUnmarshalJSON(stageBytes, &out)

			fmt.Println(out.Stage)

			return nil
		},
	}
}

func GetCmdRoundResult(queryRoute string, cdc *codec.Codec) *cobra.Command {
	return &cobra.Command{
		Use:   "get-random [round](optional)",
		Short: "returns round result random number",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cliCtx := context.NewCLIContext().WithCodec(cdc)

			var round int64
			if len(args) > 0 {
				parsedRound, err := strconv.ParseUint(args[0], 10, 64)
				if err != nil {
					return fmt.Errorf("round %s not a valid uint, please input a valid round", args[0])
				}
				round = int64(parsedRound)
			} else {
				round = -1
			}

			params := types.NewQueryByRound(round)
			bz, err := cdc.MarshalJSON(params)
			if err != nil {
				return err
			}

			resBytes, _, err := cliCtx.QueryWithData(fmt.Sprintf("custom/%s/%s", queryRoute, types.QueryResult), bz)
			if err != nil {
				return fmt.Errorf(fmt.Sprintf("%v", err))
			}

			var out types.QueryResultRes
			cdc.MustUnmarshalJSON(resBytes, &out)

			fmt.Printf("random data: %v\n", out.String())

			return nil
		},
	}
}
