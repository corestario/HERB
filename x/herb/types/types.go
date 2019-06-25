package types

import (
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// CiphertextPart represents ciphertext part and additional information for the first HERB phase.
type CiphertextPart struct {
	Ciphertext      elgamal.Ciphertext
	EntropyProvider sdk.AccAddress
}
