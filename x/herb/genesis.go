package herb

import (
	"errors"
	"flag"
	"log"
	"net/http"

	"github.com/dgamingfoundation/HERB/x/herb/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	sdk "github.com/cosmos/cosmos-sdk/types"
	abci "github.com/tendermint/tendermint/abci/types"

	kyberenc "go.dedis.ch/kyber/v3/util/encoding"
)

// NewGenesisState creates new instance GenesisState
func NewGenesisState(thresholdParts uint64, thresholdDecryption uint64) GenesisState {
	return GenesisState{
		ThresholdParts:      thresholdParts,
		ThresholdDecryption: thresholdDecryption,
		CommonPublicKey:     P256.Point().String(),
		KeyHolders:          []types.VerificationKeyJSON{},
		RoundData:           []types.RoundData{},
	}
}

// ValidateGenesis validates the provided herb genesis state to ensure the
// expected invariants holds.
func ValidateGenesis(data GenesisState) error {
	partsThreshold := data.ThresholdParts
	sharesThreshold := data.ThresholdDecryption
	if partsThreshold < 1 {
		return errors.New("theshold for ciphertext shares must be positive")
	}
	if sharesThreshold < 1 {
		return errors.New("theshold for descryption shares must be positive")
	}

	if _, err := kyberenc.StringHexToPoint(types.P256, data.CommonPublicKey); err != nil {
		return err
	}
	for _, keyHolderJSON := range data.KeyHolders {
		if _, err2 := keyHolderJSON.Deserialize(); err2 != nil {
			return errors.New(err2.Error())
		}
	}
	return nil
}

// DefaultGenesisState returns default testing genesis state
func DefaultGenesisState() GenesisState {
	return GenesisState{
		ThresholdParts:      0,
		ThresholdDecryption: 0,
		CommonPublicKey:     P256.Point().String(),
		KeyHolders:          []types.VerificationKeyJSON{},
		RoundData:           []types.RoundData{},
	}
}

// InitGenesis sets the pool and parameters for the provided keeper.
func InitGenesis(ctx sdk.Context, keeper Keeper, data GenesisState) []abci.ValidatorUpdate {
	keyHolders := data.KeyHolders

	err := keeper.SetVerificationKeys(ctx, keyHolders)
	if err != nil {
		panic(err)
	}
	var addr = flag.String("listen-address", ":8080", "The address to listen on for HTTP requests.")
	srv := &http.Server{
		Addr: *addr,
		Handler: promhttp.InstrumentMetricHandler(
			prometheus.DefaultRegisterer, promhttp.HandlerFor(
				prometheus.DefaultGatherer,
				promhttp.HandlerOpts{MaxRequestsInFlight: 3},
			),
		),
	}
	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal(http.ListenAndServe(*addr, nil))
		}
	}()
	keeper.SetKeyHoldersNumber(ctx, uint64(len(keyHolders)))
	keeper.SetThreshold(ctx, data.ThresholdParts, data.ThresholdDecryption)
	keeper.SetCommonPublicKey(ctx, data.CommonPublicKey)
	keeper.setRound(ctx, uint64(0))
	keeper.setStage(ctx, uint64(0), stageUnstarted)
	for _, rd := range data.RoundData {
		for _, ctJSON := range rd.CiphertextShares {
			ct, err := ctJSON.Deserialize()
			if err != nil {
				panic(err)
			}
			err = keeper.SetCiphertext(ctx, ct)
			if err != nil {
				panic(err)
			}
		}
		for _, dsJSON := range rd.DecryptionShares {
			ds, err := dsJSON.Deserialize()
			if err != nil {
				panic(err)
			}
			err = keeper.SetDecryptionShare(ctx, ds)
			if err != nil {
				panic(err)
			}
		}
	}
	return []abci.ValidatorUpdate{}

}

// ExportGenesis returns a GenesisState for a given context and keeper.
func ExportGenesis(ctx sdk.Context, k Keeper) GenesisState {
	tp, err := k.GetThresholdParts(ctx)
	if err != nil {
		panic(err)
	}
	td, err := k.GetThresholdDecryption(ctx)
	if err != nil {
		panic(err)
	}
	commonPK, err := k.GetCommonPublicKey(ctx)
	if err != nil {
		panic(err)
	}
	keyHolders, err := k.GetVerificationKeys(ctx)
	if err != nil {
		panic(err)
	}
	var roundData []types.RoundData
	lastRound := k.CurrentRound(ctx)
	for i := uint64(0); i < lastRound; i++ {
		var ctSharesJSON []*types.CiphertextShareJSON
		ctShares, err := k.GetAllCiphertexts(ctx, i)
		if err != nil {
			panic(err)
		}
		for _, ct := range ctShares {
			ctJSON, err := types.NewCiphertextShareJSON(ct)
			if err != nil {
				panic(err)
			}
			ctSharesJSON = append(ctSharesJSON, ctJSON)
		}
		var dSharesJSON []*types.DecryptionShareJSON
		dShares, err := k.GetAllDecryptionShares(ctx, i)
		if err != nil {
			panic(err)
		}
		for _, ds := range dShares {
			dsJSON, err := types.NewDecryptionShareJSON(ds)
			if err != nil {
				panic(err)
			}
			dSharesJSON = append(dSharesJSON, &dsJSON)
		}
		roundData = append(roundData, types.RoundData{ctSharesJSON, dSharesJSON})
	}
	cPK, err1 := kyberenc.PointToStringHex(P256, commonPK)
	if err1 != nil {
		panic(err1)
	}
	return GenesisState{
		ThresholdParts:      tp,
		ThresholdDecryption: td,
		CommonPublicKey:     cPK,
		KeyHolders:          keyHolders,
		RoundData:           roundData,
	}
}
