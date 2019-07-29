package herb

import (
	"fmt"

	"github.com/dgamingfoundation/HERB/x/herb/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// NewHandler returns a handler for "herb" type messages.
func NewHandler(keeper Keeper) sdk.Handler {
	return func(ctx sdk.Context, msg sdk.Msg) sdk.Result {
		switch msg := msg.(type) {
		case MsgSetCiphertextPart:
			return handleMsgSetCiphertextPart(ctx, &keeper, msg)
		case MsgSetDecryptionShare:
			return handleMsgSetDecryptionShare(ctx, &keeper, msg)
		default:
			errMsg := fmt.Sprintf("Unrecognized herb Msg type: %v", msg.Type())
			return sdk.ErrUnknownRequest(errMsg).Result()
		}
	}
}

func handleMsgSetCiphertextPart(ctx sdk.Context, keeper *Keeper, msg types.MsgSetCiphertextPart) sdk.Result {
	ctPart, err := msg.CiphertextPart.Deserialize()
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("coudn't deserialize ciphertext part: %v", err)).Result()
	}

	if err2 := keeper.SetCiphertext(ctx, ctPart); err2 != nil {
		return err2.Result()
	}

	return sdk.Result{}
}

func handleMsgSetDecryptionShare(ctx sdk.Context, keeper *Keeper, msg types.MsgSetDecryptionShare) sdk.Result {
	decryptionShare, err := msg.DecryptionShare.Deserialize()
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("coudn't deserialize dectyption share: %v", err)).Result()
	}
	if err2 := keeper.SetDecryptionShare(ctx, decryptionShare); err2 != nil {
		return err2.Result()
	}

	return sdk.Result{}
}
