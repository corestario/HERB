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
		default:
			return nil, sdk.ErrUnknownRequest("unknown herb query endpoint")
		}
	}
}

func queryAggregatedCt(ctx sdk.Context, req abci.RequestQuery, keeper Keeper) ([]byte, sdk.Error) {
	var params types.QueryByRound
	err := keeper.cdc.UnmarshalJSON(req.Data, &params)
	if err != nil {
		return nil, sdk.ErrUnknownRequest(sdk.AppendMsgToErr("incorrectly formatted request data", err.Error()))
	}

	aggregatedCt, err2 := keeper.GetAggregatedCiphertext(ctx, params.Round)
	if err2 != nil {
		return nil, err2
	}

	ctJSON, err := elgamal.NewCiphertextJSON(aggregatedCt)
	if err != nil {
		return nil, sdk.ErrUnknownRequest(sdk.AppendMsgToErr("coudn't get JSON ciphertext", err.Error()))
	}

	bz, err := codec.MarshalJSONIndent(keeper.cdc, ctJSON)
	if err != nil {
		return nil, sdk.ErrInternal(sdk.AppendMsgToErr("could not marshal result to JSON", err.Error()))
	}

	return bz, nil
}
func queryGetAllCt(ctx sdk.Context, req abci.RequestQuery, keeper Keeper) ([]byte, sdk.Error) {
	var params types.QueryByRound
	err := keeper.cdc.UnmarshalJSON(req.Data, &params)
	if err != nil {
		return nil, sdk.ErrUnknownRequest(sdk.AppendMsgToErr("incorrectly formatted request data", err.Error()))
	}

	allCt, err2 := keeper.GetAllCiphertexts(ctx, params.Round)
	if err2 != nil {
		return nil, err2
	}

	allCtJSON, err := types.CiphertextMapSerialize(allCt)
	if err != nil {
		return nil, sdk.ErrUnknownRequest(sdk.AppendMsgToErr("coudn't get JSON ciphertexts", err.Error()))
	}

	bz, err := codec.MarshalJSONIndent(keeper.cdc, allCtJSON)
	if err != nil {
		return nil, sdk.ErrInternal(sdk.AppendMsgToErr("could not marshal result to JSON", err.Error()))
	}

	return bz, nil
}

func queryAllDescryptionShares(ctx sdk.Context, req abci.RequestQuery, keeper Keeper) ([]byte, sdk.Error) {
	var params types.QueryByRound
	err := keeper.cdc.UnmarshalJSON(req.Data, &params)
	if err != nil {
		return nil, sdk.ErrUnknownRequest(sdk.AppendMsgToErr("incorrectly formatted request data", err.Error()))
	}

	allShares, err2 := keeper.GetAllDecryptionShares(ctx, params.Round)
	if err2 != nil {
		return nil, err2
	}

	allSharesJSON, err := types.DecryptionSharesMapSerialize(allShares)
	if err != nil {
		return nil, sdk.ErrUnknownRequest(sdk.AppendMsgToErr("coudn't get JSON decryption shares", err.Error()))
	}

	bz, err := codec.MarshalJSONIndent(keeper.cdc, allSharesJSON)
	if err != nil {
		return nil, sdk.ErrInternal(sdk.AppendMsgToErr("could not marshal result to JSON", err.Error()))
	}

	return bz, nil
}
