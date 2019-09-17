package rest

import (
	"fmt"

	"github.com/cosmos/cosmos-sdk/client/context"

	"github.com/gorilla/mux"
)

const (
	restName = "herb"
)

// RegisterRoutes - Central function to define routes that get registered by the main application
func RegisterRoutes(cliCtx context.CLIContext, r *mux.Router, storeName string) {
	r.HandleFunc(
		fmt.Sprintf("/%s/ciphertext/aggregated", storeName),
		aggregatedCiphertextHandler(cliCtx, storeName),
	).Methods("GET")
	r.HandleFunc(
		fmt.Sprintf("/%s/round/current", storeName),
		currentRoundHandler(cliCtx, storeName),
	).Methods("GET")
	r.HandleFunc(
		fmt.Sprintf("/%s/round/stage", storeName),
		roundStageHandler(cliCtx, storeName),
	).Methods("GET")
	r.HandleFunc(
		fmt.Sprintf("/%s/round/result", storeName),
		roundResultHandler(cliCtx, storeName),
	).Methods("GET")
	r.HandleFunc(
		fmt.Sprintf("/%s/ciphertext/all", storeName),
		allCiphertextHandler(cliCtx, storeName),
	).Methods("GET")
	r.HandleFunc(
		fmt.Sprintf("/%s/decryptionshares/all", storeName),
		allDecryptionSharesHandler(cliCtx, storeName),
	).Methods("GET")
	r.HandleFunc(
		fmt.Sprintf("/%s/ciphertext/set", storeName),
		setCiphertextPartHandler(cliCtx),
	).Methods("POST")
	r.HandleFunc(
		fmt.Sprintf("/%sdecryptionshares/set", storeName),
		setDecryptionShareHandler(cliCtx),
	).Methods("POST")
}
