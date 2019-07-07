package herb

import (
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
	"github.com/dgamingfoundation/HERB/x/herb/types"

	"github.com/cosmos/cosmos-sdk/codec"

	sdk "github.com/cosmos/cosmos-sdk/types"
	abci "github.com/tendermint/tendermint/abci/types"
)

// NewQuerier is the module level router for state queries
func NewQuerier(keeper Keeper) sdk.Querier {
	return func(ctx sdk.Context, path []string, req abci.RequestQuery) (res []byte, err sdk.Error) {
		switch path[0] {
		case types.QueryAggregatedCt:
			return queryAggregatedCt(ctx, req, keeper)
		case types.QueryAllCt:
			return queryGetAllCt(ctx, req, keeper)
		case types.QueryAllDescryptionShares:
			return queryAllDescryptionShares(ctx, req, keeper)
		case types.QueryRandom:
			return queryRandom(ctx, req, keeper)
		case types.QueryStage:
			return queryStage(ctx, req, keeper)
		default:
			return nil, sdk.ErrUnknownRequest("unknown herb query endpoint")
		}
	}
}

func queryAggregatedCt(ctx sdk.Context, req abci.RequestQuery, keeper Keeper) ([]byte, sdk.Error) {
	round, err := getRoundFromQuery(req, keeper)
	if err != nil {
		return  nil, err
	}

	aggregatedCt, err := keeper.GetAggregatedCiphertext(ctx, round)
	if err != nil {
		return nil, err
	}

	ctJSON, err2 := elgamal.NewCiphertextJSON(aggregatedCt)
	if err2 != nil {
		return nil, sdk.ErrUnknownRequest(sdk.AppendMsgToErr("coudn't get JSON ciphertext", err.Error()))
	}

	bz, err2 := codec.MarshalJSONIndent(keeper.cdc, ctJSON)
	if err2 != nil {
		return nil, sdk.ErrInternal(sdk.AppendMsgToErr("could not marshal result to JSON", err.Error()))
	}

	return bz, nil
}
func queryGetAllCt(ctx sdk.Context, req abci.RequestQuery, keeper Keeper) ([]byte, sdk.Error) {
	round, err := getRoundFromQuery(req, keeper)
	if err != nil {
		return  nil, err
	}

	allCt, err := keeper.GetAllCiphertexts(ctx, round)
	if err != nil {
		return nil, err
	}

	allCtJSON, err := types.CiphertextMapSerialize(allCt)
	if err != nil {
		return nil, sdk.ErrUnknownRequest(sdk.AppendMsgToErr("coudn't get JSON ciphertexts", err.Error()))
	}

	bz, err2 := codec.MarshalJSONIndent(keeper.cdc, allCtJSON)
	if err2 != nil {
		return nil, sdk.ErrInternal(sdk.AppendMsgToErr("could not marshal result to JSON", err.Error()))
	}

	return bz, nil
}

func queryAllDescryptionShares(ctx sdk.Context, req abci.RequestQuery, keeper Keeper) ([]byte, sdk.Error) {
	round, err := getRoundFromQuery(req, keeper)
	if err != nil {
		return  nil, err
	}

	allShares, err := keeper.GetAllDecryptionShares(ctx, round)
	if err != nil {
		return nil, err
	}

	allSharesJSON, err := types.DecryptionSharesMapSerialize(allShares)
	if err != nil {
		return nil, sdk.ErrUnknownRequest(sdk.AppendMsgToErr("coudn't get JSON decryption shares", err.Error()))
	}

	bz, err2 := codec.MarshalJSONIndent(keeper.cdc, allSharesJSON)
	if err2 != nil {
		return nil, sdk.ErrInternal(sdk.AppendMsgToErr("could not marshal result to JSON", err.Error()))
	}

	return bz, nil
}

func queryRandom(ctx sdk.Context, req abci.RequestQuery, keeper Keeper) ([]byte, sdk.Error) {
	round, err := getRoundFromQuery(req, keeper)
	if err != nil {
		return  nil, err
	}

	randBytes, err := keeper.GetRandom(ctx, round)
	if err != nil {
		return nil, err
	}

	return randBytes, nil
}

func queryStage(ctx sdk.Context, req abci.RequestQuery, keeper Keeper) ([]byte, sdk.Error) {
	round, err := getRoundFromQuery(req, keeper)
	if err != nil {
		return  nil, err
	}

	stage := keeper.GetStage(ctx, round)
	return []byte(stage), nil
}

func getRoundFromQuery(req abci.RequestQuery, keeper Keeper) (uint64, sdk.Error) {
	var params types.QueryByRound
	err := keeper.cdc.UnmarshalJSON(req.Data, &params)
	if err != nil {
		return 0, sdk.ErrUnknownRequest(sdk.AppendMsgToErr("incorrectly formatted request data", err.Error()))
	}

	var round uint64
	if params.Round >= 0 {
		round = uint64(params.Round)
	} else {
		round = keeper.currentRound
	}

	return round, nil
}