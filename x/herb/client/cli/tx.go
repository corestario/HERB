package cli

import (
	"fmt"
	"strconv"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/context"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/x/auth"
	"github.com/cosmos/cosmos-sdk/x/auth/client/utils"
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/dgamingfoundation/HERB/x/herb/types"

	"github.com/spf13/cobra"

	"go.dedis.ch/kyber/v3/share"
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
		Use:   "ct-part [commonPubKey]",
		Short: "send random ciphertext part",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cliCtx := context.NewCLIContext().WithCodec(cdc)

			group := types.P256
			pubKey, err := kyberenc.StringHexToPoint(group, args[0])
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
				return err
			}
			msg := types.NewMsgSetCiphertextPart(*ctPartJSON, cliCtx.GetFromAddress())
			err = msg.ValidateBasic()
			if err != nil {
				return err
			}

			return utils.GenerateOrBroadcastMsgs(cliCtx, txBldr, []sdk.Msg{msg})
		},
	}
}

// GetCmdSetDecryptionShare implements send decryption share transaction command.
func GetCmdSetDecryptionShare(cdc *codec.Codec) *cobra.Command {
	return &cobra.Command{
		Use:   "decrypt [privateKey] [ID]",
		Short: "Send a decryption share of the aggregated ciphertext",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cliCtx := context.NewCLIContext().WithCodec(cdc)

			//Getting aggregated ciphertext
			params := types.NewQueryByRound(-1) //-1 for the current round
			bz, err := cdc.MarshalJSON(params)
			if err != nil {
				return err
			}

			ctPartBytes, _, err := cliCtx.QueryWithData(fmt.Sprintf("custom/%s/%s", types.QuerierRouter, types.QueryAggregatedCt), bz)
			if err != nil {
				return err
			}

			var ctJSON elgamal.CiphertextJSON
			cdc.MustUnmarshalJSON(ctPartBytes, &ctJSON)
			aggregatedCt, err := ctJSON.Deserialize(types.P256)
			if err != nil {
				return err
			}

			//decrypting ciphertext
			group := types.P256
			privKey, err := kyberenc.StringHexToScalar(group, args[0])
			if err != nil {
				return fmt.Errorf("failed to decode private key: %v", err)
			}

			id, err := strconv.ParseInt(args[1], 10, 64)
			if err != nil {
				return fmt.Errorf("id %s not a valid int, please input a valid id", args[1])
			}

			sharePoint, proof, err := elgamal.CreateDecShare(group, *aggregatedCt, privKey)

			decryptionShare := &types.DecryptionShare{
				DecShare:  share.PubShare{I: int(id), V: sharePoint},
				DLEproof:  proof,
				KeyHolder: cliCtx.GetFromAddress(),
			}

			txBldr := auth.NewTxBuilderFromCLI().WithTxEncoder(utils.GetTxEncoder(cdc))

			decryptionShareJSON, err := types.NewDecryptionShareJSON(decryptionShare)
			msg := types.NewMsgSetDecryptionShare(*decryptionShareJSON, cliCtx.GetFromAddress())
			err = msg.ValidateBasic()
			if err != nil {
				return err
			}

			return utils.GenerateOrBroadcastMsgs(cliCtx, txBldr, []sdk.Msg{msg})
		},
	}
}
