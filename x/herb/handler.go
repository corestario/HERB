package herb

import (
    "fmt"

    "github.com/dgamingfoundation/herb/types"
    
    sdk "github.com/cosmos/cosmos-sdk/types"
)

// NewHandler returns a handler for "herb" type messages.
func NewHandler(keeper Keeper) sdk.Handler {
	return func(ctx sdk.Context, msg sdk.Msg) sdk.Result {
        switch msg := msg.Type() {
            
        }
    } 
}