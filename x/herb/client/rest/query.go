package rest

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/dgamingfoundation/HERB/x/herb/types"

	"github.com/cosmos/cosmos-sdk/client/context"
	"github.com/cosmos/cosmos-sdk/types/rest"

	"github.com/gorilla/mux"
)

func aggregatedCiphertextHandler(cliCtx context.CLIContext, storeName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)

		roundStr := vars["round"]

		var round int64
		if len(roundStr) > 0 {
			parsedRound, err := strconv.ParseUint(roundStr, 10, 64)
			if err != nil {
				rest.WriteErrorResponse(w, http.StatusBadRequest, fmt.Errorf("round %s not a valid uint, please input a valid round", roundStr).Error())
			}
			round = int64(parsedRound)
		} else {
			round = -1
		}

		params := types.NewQueryByRound(round)
		cdc := cliCtx.Codec
		bz, err := cdc.MarshalJSON(params)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}

		res, _, err := cliCtx.QueryWithData(fmt.Sprintf("custom/%s/%s", storeName, types.QueryAggregatedCt), bz)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusNotFound, err.Error())
		}

		rest.PostProcessResponse(w, cliCtx, res)
	}
}

func currentRoundHandler(cliCtx context.CLIContext, storeName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res, _, err := cliCtx.QueryWithData(fmt.Sprintf("custom/%s/%s", storeName, types.QueryCurrentRound), nil)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusNotFound, err.Error())
			return
		}

		rest.PostProcessResponse(w, cliCtx, res)
	}
}

func roundStageHandler(cliCtx context.CLIContext, storeName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)

		roundStr := vars["round"]

		var round int64
		if len(roundStr) > 0 {
			parsedRound, err := strconv.ParseUint(roundStr, 10, 64)
			if err != nil {
				rest.WriteErrorResponse(w, http.StatusBadRequest, fmt.Errorf("round %s not a valid uint, please input a valid round", roundStr).Error())
			}
			round = int64(parsedRound)
		} else {
			round = -1
		}

		params := types.NewQueryByRound(round)
		cdc := cliCtx.Codec
		bz, err := cdc.MarshalJSON(params)

		if err != nil {
			rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}

		res, _, err := cliCtx.QueryWithData(fmt.Sprintf("custom/%s/%s", storeName, types.QueryStage), bz)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}

		rest.PostProcessResponse(w, cliCtx, res)
	}
}

func roundResultHandler(cliCtx context.CLIContext, storeName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)

		roundStr := vars["round"]

		var round int64
		if len(roundStr) > 0 {
			parsedRound, err := strconv.ParseUint(roundStr, 10, 64)
			if err != nil {
				rest.WriteErrorResponse(w, http.StatusBadRequest, fmt.Errorf("round %s not a valid uint, please input a valid round", roundStr).Error())
			}
			round = int64(parsedRound)
		} else {
			round = -1
		}

		params := types.NewQueryByRound(round)
		cdc := cliCtx.Codec
		bz, err := cdc.MarshalJSON(params)

		if err != nil {
			rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}

		resBytes, _, err := cliCtx.QueryWithData(fmt.Sprintf("custom/%s/%s", storeName, types.QueryResult), bz)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}

		rest.PostProcessResponse(w, cliCtx, resBytes)
	}
}

func allCiphertextHandler(cliCtx context.CLIContext, storeName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)

		roundStr := vars["round"]

		var round int64
		if len(roundStr) > 0 {
			parsedRound, err := strconv.ParseUint(roundStr, 10, 64)
			if err != nil {
				rest.WriteErrorResponse(w, http.StatusBadRequest, fmt.Errorf("round %s not a valid uint, please input a valid round", roundStr).Error())
			}
			round = int64(parsedRound)
		} else {
			round = -1
		}

		params := types.NewQueryByRound(round)
		cdc := cliCtx.Codec
		bz, err := cdc.MarshalJSON(params)

		if err != nil {
			rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}

		res, _, err := cliCtx.QueryWithData(fmt.Sprintf("custom/%s/%s", storeName, types.QueryAllCt), bz)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusNotFound, err.Error())
			return
		}

		rest.PostProcessResponse(w, cliCtx, res)
	}
}

func allDecryptionSharesHandler(cliCtx context.CLIContext, storeName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)

		roundStr := vars["round"]

		var round int64
		if len(roundStr) > 0 {
			parsedRound, err := strconv.ParseUint(roundStr, 10, 64)
			if err != nil {
				rest.WriteErrorResponse(w, http.StatusBadRequest, fmt.Errorf("round %s not a valid uint, please input a valid round", roundStr).Error())
			}
			round = int64(parsedRound)
		} else {
			round = -1
		}

		params := types.NewQueryByRound(round)
		cdc := cliCtx.Codec
		bz, err := cdc.MarshalJSON(params)

		if err != nil {
			rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}

		res, _, err := cliCtx.QueryWithData(fmt.Sprintf("custom/%s/%s", storeName, types.QueryAllDescryptionShares), bz)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusNotFound, err.Error())
			return
		}

		rest.PostProcessResponse(w, cliCtx, res)
	}
}
