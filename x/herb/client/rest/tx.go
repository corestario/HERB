package rest

import (
	"net/http"
	"strings"

	"github.com/cosmos/cosmos-sdk/client/context"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/rest"
	"github.com/cosmos/cosmos-sdk/x/auth/client/utils"

	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
	"github.com/dgamingfoundation/HERB/x/herb/types"

	kyberenc "go.dedis.ch/kyber/v3/util/encoding"
)

type setCiphertextPartReq struct {
	BaseReq         rest.BaseReq `jcon:"base_req"`
	Ciphertext      string       `json:"ciphertext"`
	CEProof         string       `json:"ce_proof"`
	EntropyProvider string       `json:"entropy_provider"`
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

		entropyProvider, err := sdk.AccAddressFromBech32(req.EntropyProvider)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
			return
		}

		// ciphertext is representes as '(point_A, point_B)'
		points := strings.Split(req.Ciphertext, ",")
		points[0] = strings.TrimPrefix(points[0], "(")
		points[1] = strings.TrimSuffix(points[1], ")")

		pointA, err := kyberenc.StringHexToPoint(types.P256, points[0])
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
			return
		}
		pointB, err := kyberenc.StringHexToPoint(types.P256, points[1])
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
			return
		}
		ct := elgamal.Ciphertext{PointA: pointA, PointB: pointB}
		ctJSON, err := elgamal.NewCiphertextJSON(&ct, types.P256)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
			return
		}

		ctPart := types.CiphertextPartJSON{*ctJSON, []byte(req.CEProof), entropyProvider}

		msg := types.NewMsgSetCiphertextPart(ctPart, entropyProvider)

		err = msg.ValidateBasic()
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
			return
		}

		utils.WriteGenerateStdTxResponse(w, cliCtx, req.BaseReq, []sdk.Msg{msg})
	}
}

type setDecryptionShareReq struct {
	BaseReq         rest.BaseReq `jcon:"base_req"`
	DecryptionShare string       `json:"decryption_share"`
	DLEProof        string       `json:"dle_proof"`
	KeyHolder       string       `json:"key_holder"`
}

func setDecryptionShareHandler(cliCtx context.CLIContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cdc := cliCtx.Codec
		var req setDecryptionShareReq

		if !rest.ReadRESTReq(w, r, cdc, &req) {
			rest.WriteErrorResponse(w, http.StatusBadRequest, "failed to parse request")
			return
		}

		baseReq := req.BaseReq.Sanitize()
		if !baseReq.ValidateBasic(w) {
			return
		}

		keyHolder, err := sdk.AccAddressFromBech32(req.KeyHolder)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
			return
		}

		decShare := types.DecryptionShareJSON{DecShare: req.DecryptionShare, DLEproof: req.DLEProof, KeyHolderAddr: keyHolder}
		msg := types.NewMsgSetDecryptionShare(decShare, keyHolder)

		err = msg.ValidateBasic()
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
			return
		}

		utils.WriteGenerateStdTxResponse(w, cliCtx, req.BaseReq, []sdk.Msg{msg})
	}
}
