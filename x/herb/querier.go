package herb

import (
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
	"github.com/dgamingfoundation/HERB/x/herb/types"

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
		case types.QueryStage:
			return queryStage(ctx, req, keeper)
		case types.QueryCurrentRound:
			return queryCurrentRound(ctx, keeper)
		case types.QueryResult:
			return queryResult(ctx, req, keeper)
		default:
			return nil, sdk.ErrUnknownRequest("unknown herb query endpoint")
		}
	}
}

func queryAggregatedCt(ctx sdk.Context, req abci.RequestQuery, keeper Keeper) ([]byte, sdk.Error) {
	round, err := getRoundFromQuery(ctx, req, keeper)
	if err != nil {
		return nil, err
	}

	aggregatedCt, err := keeper.GetAggregatedCiphertext(ctx, round)
	if err != nil {
		return nil, err
	}

	ctJSON, err2 := elgamal.NewCiphertextJSON(aggregatedCt, P256)
	if err2 != nil {
		return nil, sdk.ErrInternal(sdk.AppendMsgToErr("coudn't get JSON ciphertext", err2.Error()))
	}

	resBytes, err2 := codec.MarshalJSONIndent(keeper.cdc, types.QueryAggregatedCtRes{*ctJSON})
	if err2 != nil {
		return nil, sdk.ErrInternal(sdk.AppendMsgToErr("could not marshal result to JSON", err2.Error()))
	}

	return resBytes, nil
}
func queryGetAllCt(ctx sdk.Context, req abci.RequestQuery, keeper Keeper) ([]byte, sdk.Error) {
	round, err := getRoundFromQuery(ctx, req, keeper)
	if err != nil {
		return nil, err
	}

	allCt, err := keeper.GetAllCiphertexts(ctx, round)
	if err != nil {
		return nil, err
	}

	allCtJSON, err := types.CiphertextArraySerialize(allCt)
	if err != nil {
		return nil, err
	}

	bz, err2 := codec.MarshalJSONIndent(keeper.cdc, types.QueryAllCtRes{allCtJSON})
	if err2 != nil {
		return nil, sdk.ErrInternal(sdk.AppendMsgToErr("could not marshal result to JSON", err2.Error()))
	}

	return bz, nil
}

func queryAllDescryptionShares(ctx sdk.Context, req abci.RequestQuery, keeper Keeper) ([]byte, sdk.Error) {
	round, err := getRoundFromQuery(ctx, req, keeper)
	if err != nil {
		return nil, err
	}

	allShares, err := keeper.GetAllDecryptionShares(ctx, round)
	if err != nil {
		return nil, err
	}

	allSharesJSON, err := types.DecryptionSharesArraySerialize(allShares)
	if err != nil {
		return nil, err
	}

	resBytes, err2 := codec.MarshalJSONIndent(keeper.cdc, types.QueryAllDescryptionSharesRes{allSharesJSON})
	if err2 != nil {
		return nil, sdk.ErrInternal(sdk.AppendMsgToErr("could not marshal result to JSON", err2.Error()))
	}

	return resBytes, nil
}

func queryStage(ctx sdk.Context, req abci.RequestQuery, keeper Keeper) ([]byte, sdk.Error) {
	round, err := getRoundFromQuery(ctx, req, keeper)
	if err != nil {
		return nil, err
	}

	stage := keeper.GetStage(ctx, round)

	res, err2 := codec.MarshalJSONIndent(keeper.cdc, types.QueryStageRes{stage})
	if err2 != nil {
		return nil, sdk.ErrInternal(sdk.AppendMsgToErr("stage marshaling failed", err2.Error()))
	}

	return res, nil
}

func queryCurrentRound(ctx sdk.Context, keeper Keeper) ([]byte, sdk.Error) {
	round := keeper.CurrentRound(ctx)

	res, err := codec.MarshalJSONIndent(keeper.cdc, types.QueryCurrentRoundRes{round})
	if err != nil {
		return nil, sdk.ErrInternal(sdk.AppendMsgToErr("round marshaling failed", err.Error()))
	}

	return res, nil
}

func queryResult(ctx sdk.Context, req abci.RequestQuery, keeper Keeper) ([]byte, sdk.Error) {
	round, err := getRoundFromQuery(ctx, req, keeper)
	if err != nil {
		return nil, err
	}
	
	if round == keeper.CurrentRound(ctx) {
		round = round - 1
	}

	randomBytes, err := keeper.RandomResult(ctx, round)

	if err != nil {
		return nil, err
	}

	res, err2 := codec.MarshalJSONIndent(keeper.cdc, types.QueryResultRes{randomBytes})
	if err2 != nil {
		return nil, sdk.ErrInternal(sdk.AppendMsgToErr("random results marshaling failed", err2.Error()))
	}

	return res, nil
}

func getRoundFromQuery(ctx sdk.Context, req abci.RequestQuery, keeper Keeper) (uint64, sdk.Error) {
	var params types.QueryByRound
	err := keeper.cdc.UnmarshalJSON(req.Data, &params)
	if err != nil {
		return 0, sdk.ErrUnknownRequest(sdk.AppendMsgToErr("incorrectly formatted request data", err.Error()))
	}

	var round uint64
	if params.Round >= 0 {
		round = uint64(params.Round)
	} else {
		round = keeper.CurrentRound(ctx)
	}

	return round, nil
}
