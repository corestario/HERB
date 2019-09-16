package rest

import (
	"net/http"

	"github.com/dgamingfoundation/HERB/x/herb/types"

	"github.com/cosmos/cosmos-sdk/client/context"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/rest"
	"github.com/cosmos/cosmos-sdk/x/auth/client/utils"
)

type setCiphertextPartReq struct {
	BaseReq         rest.BaseReq `jcon:"base_req"`
	Round           string       `json:"round"`
	Ciphertext      string       `json:"ciphertext"`
	EntropyProvider string       `json:"entropy_provider"`
	Sender          string       `json:"entropyProvider"`
}

func setCiphertextPartHandler(cliCtx context.CLIContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cdc := cliCtx.Codec
		var req setCiphertextPartReq

		if !rest.ReadRESTReq(w, r, cdc, &req) {
			rest.WriteErrorResponse(w, http.StatusBadRequest, "failed to parse request")
			return
		}

		baseReq := req.BaseReq.Sanitize()
		if !baseReq.ValidateBasic(w) {
			return
		}

		sender, err := sdk.AccAddressFromBech32(req.Sender)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
			return
		}

		entropyProvider, err := sdk.AccAddressFromBech32(req.EntropyProvider)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
			return
		}

		ctPart := types.CiphertextPartJSON{req.Ciphertext, []byte{}, []byte{}, entropyProvider}

		msg := types.NewMsgSetCiphertextPart(ctPart, sender)

		err = msg.ValidateBasic()
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
			return
		}

		utils.WriteGenerateStdTxResponse(w, cliCtx, req.BaseReq, []sdk.Msg{msg})
	}
}
