package herb

import (
	"github.com/dgamingfoundation/HERB/x/herb/types"
)

const (
	ModuleName = types.ModuleName
	RouterKey  = types.RouterKey
	StoreKey   = types.StoreKey
	CtStoreKey = types.CtStoreKey
	DsStoreKey = types.DsStoreKey
)

var (
	NewMsgSetCiphertextPart = types.NewMsgSetCiphertextPart
	ModuleCdc               = types.ModuleCdc
	RegisterCodec           = types.RegisterCodec
	P256                    = types.P256
)

type (
	MsgSetCiphertextPart  = types.MsgSetCiphertextPart
	MsgSetRandomResult    = types.MsgSetRandomResult
	MsgSetDecryptionShare = types.MsgSetDecryptionShare
	CiphertextPart        = types.CiphertextPart
	CiphertextPartJSON    = types.CiphertextPartJSON
	DecryptionShare       = types.DecryptionShare
	DecryptionShareJSON   = types.DecryptionShareJSON
	GenesisState          = types.GenesisState
)
