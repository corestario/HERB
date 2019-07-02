package cli

import (
	"fmt"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/context"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/x/auth"
	"github.com/cosmos/cosmos-sdk/x/auth/client/utils"
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
	"strconv"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/dgamingfoundation/HERB/x/herb/types"

	"github.com/spf13/cobra"

	kyberenc "go.dedis.ch/kyber/v3/util/encoding"
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
		GetCmdSetDecryptionShare(cdc),
	)...)

	return nameserviceTxCmd
}

// GetCmdSetCiphertext implements send ciphertext part transaction command.
func GetCmdSetCiphertextPart(cdc *codec.Codec) *cobra.Command {
	return &cobra.Command{
		Use: "ctPart [round] [commonPubKey]",
		Short: "send random ciphertextPart",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cliCtx := context.NewCLIContext().WithCodec(cdc)

			round, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("round %s not a valid uint, please input a valid round", args[0])
			}

			group := types.P256
			pubKey, err := kyberenc.StringHexToPoint(group, args[1])
			if err != nil {
				return fmt.Errorf("failed to decode common public key: %v", err)
			}

			txBldr := auth.NewTxBuilderFromCLI().WithTxEncoder(utils.GetTxEncoder(cdc))

			ct, dlkProof, rkProof, err := elgamal.RandomCiphertext(group, pubKey)
			if err != nil {
				return fmt.Errorf("failed to create random ciphertext: %v", err)
			}

			sender := cliCtx.GetFromAddress()
			ctPart := types.CiphertextPart{ct, dlkProof, rkProof, sender}
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

// GetCmdSetDecryptionShare implements send decryption share transaction command.
func GetCmdSetDecryptionShare(cdc *codec.Codec) *cobra.Command {
	return &cobra.Command{
		Use: "decrypt [round] [privateKey]",
		Short: "Send a decryption share of the aggregated ciphertext for the [round]",
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			cliCtx := context.NewCLIContext().WithCodec(cdc)

			round, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("round %s not a valid uint, please input a valid round", args[0])
			}
			//Getting aggregated ciphertext
			params := types.NewQueryByRound(round)
			bz, err := cdc.MarshalJSON(params)
			if err != nil {
				return err
			}

			ctPartBytes, _, err := cliCtx.QueryWithData(fmt.Sprintf("custom/%s/%s", types.QuerierRouter, types.QueryAggregatedCt), bz)
			if err != nil {
				return err
			}

			var outJSON elgamal.CiphertextJSON
			cdc.MustUnmarshalJSON(ctPartBytes, &outJSON)
			aggregatedCt, err := outJSON.Deserialize()
			if err != nil {
				return err
			}

			group := types.P256
			privKey, err := kyberenc.StringHexToScalar(group, args[1])
			if err != nil {
				return fmt.Errorf("failed to decode common public key: %v", err)
			}

			sharePoint, proof, err := elgamal.CreateDecShare(group, *aggregatedCt, privKey)

			decryptionShare := &types.DecryptionShare{
				DecShare:  sharePoint,
				DLEproof:  proof,
				KeyHolder: cliCtx.GetFromAddress(),
			}

			txBldr := auth.NewTxBuilderFromCLI().WithTxEncoder(utils.GetTxEncoder(cdc))

			decryptionShareJSON, err := types.NewDecryptionShareJSON(decryptionShare)
			msg := types.NewMsgSetDecryptionShare(round, *decryptionShareJSON, cliCtx.GetFromAddress())
			err = msg.ValidateBasic()
			if err != nil {
				return err
			}

			return utils.GenerateOrBroadcastMsgs(cliCtx, txBldr, []sdk.Msg{msg})
		},
	}
}
