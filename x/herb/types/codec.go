package types

import (
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
)

var ModuleCdc = codec.New()

func init() {
	RegisterCodec(ModuleCdc)
}

// RegisterCodec registers concrete types on the Amino codec
func RegisterCodec(cdc *codec.Codec) {
	cdc.RegisterConcrete(MsgSetCiphertextPart{}, "herb/MsgSetCiphertextPart", nil)

	cdc.RegisterConcrete(elgamal.Ciphertext{}, "elgamal/ciphertext", nil)
}
