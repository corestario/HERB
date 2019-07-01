package cli

import (
	"fmt"
	"strconv"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/client/context"
	"github.com/cosmos/cosmos-sdk/x/auth"
	"github.com/cosmos/cosmos-sdk/x/auth/client/utils"
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/dgamingfoundation/HERB/x/herb/types"

	"github.com/spf13/cobra"

	"go.dedis.ch/kyber/v3/group/nist"
)

// GetTxCmd returns the transaction commands for this module
func GetTxCmd(storeKey string, cdc *codec.Codec) *cobra.Command {
	nameserviceTxCmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      "HERB transaction subcommands",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	nameserviceTxCmd.AddCommand(client.PostCommands(
		GetCmdSetCiphertextPart(cdc),
	)...)

	return nameserviceTxCmd
}

// GetCmdSetCiphertext implements send ciphertext part transaction command.
func GetCmdSetCiphertextPart(cdc *codec.Codec) *cobra.Command {
	return &cobra.Command{
		Use: "ctPart [multiplayer]",
		Short: "send ciphertextPart",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cliCtx := context.NewCLIContext().WithCodec(cdc)

			round := uint64(0)

			txBldr := auth.NewTxBuilderFromCLI().WithTxEncoder(utils.GetTxEncoder(cdc))

			mult, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("mult %s not a valid uint, please input a valid proposal-id", args[0])
			}

			suite := nist.NewBlakeSHA256P256()
			multScalar := suite.Scalar().SetInt64(mult)
			A := suite.Point().Mul(multScalar, nil)
			B := suite.Point().Mul(suite.Scalar().One(), nil)
			ct := elgamal.Ciphertext{A, B}
			sender := cliCtx.GetFromAddress()
			ctPart := types.CiphertextPart{ct, sender}
			ctPartJSON, err := types.NewCiphertextPartJSON(&ctPart)
			if err != nil {
				return  err
			}
			msg := types.NewMsgSetCiphertextPart(round, *ctPartJSON, cliCtx.GetFromAddress())
			err = msg.ValidateBasic()
			if err != nil {
				return  err
			}

			return utils.GenerateOrBroadcastMsgs(cliCtx, txBldr, []sdk.Msg{msg})
		},
	}
}
