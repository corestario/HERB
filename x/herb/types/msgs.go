package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// RouterKey is they name of the herb module
const RouterKey = ModuleName

// MsgSetCiphertextPart defines message for the first HERB phase (collecting ciphertext part)
type MsgSetCiphertextPart struct {
	EntropyProvider sdk.AccAddress
}

// NewMsgSetCiphertextPart is a constructor for set ciphertext part message (first HERB phase)
func NewMsgSetCiphertextPart(entropyProvider sdk.AccAddress) MsgSetCiphertextPart {
	return MsgSetCiphertextPart{
		EntropyProvider: entropyProvider,
	}
}

// Route returns the name of the module
func (msg MsgSetCiphertextPart) Route() string { return RouterKey }

// Type returns the action
func (msg MsgSetCiphertextPart) Type() string { return "setCiphertextPart" }

// ValidateBasic runs stateless checks on the message
func (msg MsgSetCiphertextPart) ValidateBasic() sdk.Error {
	if msg.EntropyProvider.Empty() {
		return sdk.ErrInvalidAddress("missing entropyProvider address")
	}

	return nil
}

// GetSignBytes encodes the message for signing
func (msg MsgSetCiphertextPart) GetSignBytes() []byte {
	return sdk.MustSortJSON(ModuleCdc.MustMarshalJSON(msg))
}

// GetSigners defines whose signature is required
func (msg MsgSetCiphertextPart) GetSigners() []sdk.AccAddress {
	return []sdk.AccAddress{msg.EntropyProvider}
}
