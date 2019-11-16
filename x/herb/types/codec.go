package types

import (
	"github.com/corestario/HERB/x/herb/elgamal"
	"github.com/cosmos/cosmos-sdk/codec"
)

var ModuleCdc = codec.New()

func init() {
	RegisterCodec(ModuleCdc)
}

// RegisterCodec registers concrete types on the Amino codec
func RegisterCodec(cdc *codec.Codec) {
	cdc.RegisterConcrete(MsgSetCiphertextShare{}, "herb/MsgSetCiphertextShare", nil)
	cdc.RegisterConcrete(MsgSetDecryptionShare{}, "herb/MsgSetDecryptionShare", nil)
	cdc.RegisterConcrete(CiphertextShareJSON{}, "herb/CiphertextShareJSON", nil)
	cdc.RegisterConcrete(CiphertextShare{}, "herb/CiphertextShare", nil)

	cdc.RegisterConcrete(elgamal.Ciphertext{}, "elgamal/ciphertext", nil)
}
