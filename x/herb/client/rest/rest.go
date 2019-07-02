package rest

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/dgamingfoundation/HERB/x/herb/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/context"
	"github.com/cosmos/cosmos-sdk/types/rest"
	"github.com/cosmos/cosmos-sdk/x/auth/client/utils"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/gorilla/mux"
)

// RegisterRoutes - Central function to define routes that get registered by the main application
func RegisterRoutes(cliCtx context.CLIContext, r *mux.Router, storeName string) {
	r.HandleFunc(
		fmt.Sprintf("%s/ciphertexts/aggregated", storeName),
		getAggregatedCiphertextHandler(cliCtx, storeName),
	).Methods("GET")
	r.HandleFunc(
		fmt.Sprintf("%s/ciphertext_part", storeName),
		setCiphertextPartHandler(cliCtx),
	).Methods("POST")
}

// QUERIES

func getAggregatedCiphertextHandler(cliCtx client.CLIContext, storeName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cdc := cliCtx.Codec
		vars := mux.Vars(r)
		param := vars["round"]

		round, err := strconv.ParseUint(param, 10, 64)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
			return
		}
		params := types.NewQueryCtParams(round)
		bz, err := cdc.MarshalJSON(params)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}

		res, _, err := cliCtx.QueryWithData(fmt.Sprintf("custom/%s/%s", storeName, types.QueryAggregatedCt), bz)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusNotFound, err.Error())
			return
		}

		rest.PostProcessResponse(w, cliCtx, res)
	}
}

// TXS

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

		round, err := strconv.ParseUint(req.Round, 10, 64)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
			return
		}

		entropyProvider, err := sdk.AccAddressFromBech32(req.EntropyProvider)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
			return
		}

		ctPart := types.CiphertextPartJSON{req.Ciphertext, entropyProvider}

		msg := types.NewMsgSetCiphertextPart(round, ctPart, sender)

		err = msg.ValidateBasic()
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
			return
		}

		utils.WriteGenerateStdTxResponse(w, cliCtx, req.BaseReq, []sdk.Msg{msg})
	}
}
