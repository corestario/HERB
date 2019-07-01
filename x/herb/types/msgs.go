package types

import (
	"fmt"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// RouterKey is they name of the herb module
const RouterKey = ModuleName

// MsgSetCiphertextPart defines message for the first HERB phase (collecting ciphertext part)
type MsgSetCiphertextPart struct {
	Round  uint64         `json:"round"`
	CiphertextPart CiphertextPartJSON    `json:"ciphertextPart"`
	Sender sdk.AccAddress `json:"sender"`
}

// NewMsgSetCiphertextPart is a constructor for set ciphertext part message (first HERB phase)
func NewMsgSetCiphertextPart(round uint64, ctPart CiphertextPartJSON, sender sdk.AccAddress) MsgSetCiphertextPart {
	return MsgSetCiphertextPart{
		Round: round,
		CiphertextPart: ctPart,
		Sender: sender,
	}
}

// Route returns the name of the module
func (msg MsgSetCiphertextPart) Route() string { return RouterKey }

// Type returns the action
func (msg MsgSetCiphertextPart) Type() string { return "setCiphertextPart" }

// ValidateBasic runs stateless checks on the message
func (msg MsgSetCiphertextPart) ValidateBasic() sdk.Error {
	if msg.Sender.Empty() {
		return sdk.ErrInvalidAddress("missing entropyProvider address")
	}

	ctPart, err := msg.CiphertextPart.Deserialize()

	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("Coudn't deserialaize ciphertext: %v", err))
	}

	if !ctPart.EntropyProvider.Equals(msg.Sender) {
		return sdk.ErrUnauthorized("Entropy provider and sender are not equal")
	}

	return nil
}

// GetSignBytes encodes the message for signing
func (msg MsgSetCiphertextPart) GetSignBytes() []byte {
	return sdk.MustSortJSON(ModuleCdc.MustMarshalJSON(msg))
}

// GetSigners defines whose signature is required
func (msg MsgSetCiphertextPart) GetSigners() []sdk.AccAddress {
	return []sdk.AccAddress{msg.Sender}
}
