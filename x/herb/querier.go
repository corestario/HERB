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
			return queryAggregatedCt(ctx, path[1:], req, keeper)
		default:
			return nil, sdk.ErrUnknownRequest("unknown nameservice query endpoint")
		}
	}
}

func queryAggregatedCt(ctx sdk.Context, path []string, req abci.RequestQuery, keeper Keeper) ([]byte, sdk.Error) {
	var params types.QueryAggregatedCtParams
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