package herb

import (
	"encoding/binary"

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
		return nil, sdk.ErrUnknownRequest(sdk.AppendMsgToErr("coudn't get JSON ciphertext", err2.Error()))
	}

	bz, err2 := codec.MarshalJSONIndent(keeper.cdc, ctJSON)
	if err2 != nil {
		return nil, sdk.ErrInternal(sdk.AppendMsgToErr("could not marshal result to JSON", err2.Error()))
	}

	return bz, nil
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
		return nil, sdk.ErrUnknownRequest(sdk.AppendMsgToErr("coudn't get JSON ciphertexts", err.Error()))
	}

	bz, err2 := codec.MarshalJSONIndent(keeper.cdc, allCtJSON)
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
		return nil, sdk.ErrUnknownRequest(sdk.AppendMsgToErr("coudn't get JSON decryption shares", err.Error()))
	}

	bz, err2 := codec.MarshalJSONIndent(keeper.cdc, allSharesJSON)
	if err2 != nil {
		return nil, sdk.ErrInternal(sdk.AppendMsgToErr("could not marshal result to JSON", err2.Error()))
	}

	return bz, nil
}

func queryStage(ctx sdk.Context, req abci.RequestQuery, keeper Keeper) ([]byte, sdk.Error) {
	round, err := getRoundFromQuery(ctx, req, keeper)
	if err != nil {
		return nil, err
	}

	stage := keeper.GetStage(ctx, round)
	return []byte(stage), nil
}

func queryCurrentRound(ctx sdk.Context, keeper Keeper) ([]byte, sdk.Error) {
	round := keeper.CurrentRound(ctx)
	roundBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(roundBytes, round)
	return roundBytes, nil
}

func queryResult(ctx sdk.Context, req abci.RequestQuery, keeper Keeper) ([]byte, sdk.Error) {
	round, err := getRoundFromQuery(ctx, req, keeper)
	if err != nil {
		return nil, err
	}
	round = round - 1
	res, err := keeper.RandomResult(ctx, round)
	if err != nil {
		return nil, err
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
