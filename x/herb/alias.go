package herb

import (
	"github.com/dgamingfoundation/HERB/x/herb/types"
)

const (
	ModuleName = types.ModuleName
	RouterKey = types.RouterKey
	StoreKey = types.StoreKey
)

var (
	NewMsgSetCiphertextPart = types.NewMsgSetCiphertextPart
	ModuleCdc = types.ModuleCdc
	RegisterCodec = types.RegisterCodec
)

type (
	MsgSetCiphertextPart = types.MsgSetCiphertextPart
)
