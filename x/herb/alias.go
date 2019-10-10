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
	NewMsgSetCiphertextShare = types.NewMsgSetCiphertextShare
	ModuleCdc               = types.ModuleCdc
	RegisterCodec           = types.RegisterCodec
	P256                    = types.P256
)

type (
	MsgSetCiphertextShare  = types.MsgSetCiphertextShare
	MsgSetDecryptionShare = types.MsgSetDecryptionShare
	CiphertextShare        = types.CiphertextShare
	CiphertextShareJSON    = types.CiphertextShareJSON
	DecryptionShare       = types.DecryptionShare
	DecryptionShareJSON   = types.DecryptionShareJSON
	GenesisState          = types.GenesisState
)
