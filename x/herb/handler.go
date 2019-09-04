package herb

import (
	"fmt"
	"log"

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
		case MsgSetRandomResult:
			return handleMsgSetRandomResult(ctx, &keeper, msg)
		default:
			errMsg := fmt.Sprintf("unrecognized herb Msg type: %v", msg.Type())
			return sdk.ErrUnknownRequest(errMsg).Result()
		}
	}
}

func handleMsgSetCiphertextPart(ctx sdk.Context, keeper *Keeper, msg types.MsgSetCiphertextPart) sdk.Result {
	ctPart, err := msg.CiphertextPart.Deserialize()
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't deserialize ciphertext part: %v", err)).Result()
	}
	if err := keeper.SetCiphertext(ctx, ctPart); err != nil {
		return err.Result()
	}
	return sdk.Result{}
}

func handleMsgSetDecryptionShare(ctx sdk.Context, keeper *Keeper, msg types.MsgSetDecryptionShare) sdk.Result {
	decryptionShare, err := msg.DecryptionShare.Deserialize()
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't deserialize decryption share: %v", err)).Result()
	}
	if err := keeper.SetDecryptionShare(ctx, decryptionShare); err != nil {
		return err.Result()
	}
	return sdk.Result{}
}
func handleMsgSetRandomResult(ctx sdk.Context, keeper *Keeper, msg types.MsgSetRandomResult) sdk.Result {
	err := keeper.SetRandomResult(ctx, msg.Round)
	defer func() {
		if r := recover(); r != nil {
			log.Println("PANIC:", r)
		}
	}()
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't set random result: %v", err)).Result()
	}
	return sdk.Result{}
}
