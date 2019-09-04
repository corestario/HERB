package types

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// RouterKey is they name of the herb module
const RouterKey = ModuleName

// MsgSetCiphertextPart defines message for the first HERB phase (collecting ciphertext part)
type MsgSetCiphertextPart struct {
	CiphertextPart CiphertextPartJSON `json:"ciphertext_part"`
	Sender         sdk.AccAddress     `json:"sender"`
}

// NewMsgSetCiphertextPart is a constructor for set ciphertext part message (first HERB phase)
func NewMsgSetCiphertextPart(ctPart CiphertextPartJSON, sender sdk.AccAddress) MsgSetCiphertextPart {
	return MsgSetCiphertextPart{
		CiphertextPart: ctPart,
		Sender:         sender,
	}
}

// Route returns the name of the module
func (msg MsgSetCiphertextPart) Route() string { return RouterKey }

// Type returns the action
func (msg MsgSetCiphertextPart) Type() string { return "setCiphertextPart" }

// ValidateBasic runs stateless checks on the message
func (msg MsgSetCiphertextPart) ValidateBasic() sdk.Error {
	if msg.Sender.Empty() {
		return sdk.ErrInvalidAddress("missing entropy provider address")
	}

	ctPart, err := msg.CiphertextPart.Deserialize()

	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't deserialaize ciphertext: %v", err))
	}

	if !ctPart.EntropyProvider.Equals(msg.Sender) {
		return sdk.ErrUnauthorized("entropy provider and sender are not equal")
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

// MsgSetCiphertextPart defines message for the first HERB phase (collecting ciphertext part)
type MsgSetDecryptionShare struct {
	DecryptionShare DecryptionShareJSON `json:"decryption_share"`
	Sender          sdk.AccAddress      `json:"sender"`
}

// NewMsgSetCiphertextPart is a constructor for set ciphertext part message (first HERB phase)
func NewMsgSetDecryptionShare(decryptionShare DecryptionShareJSON, sender sdk.AccAddress) MsgSetDecryptionShare {
	return MsgSetDecryptionShare{
		DecryptionShare: decryptionShare,
		Sender:          sender,
	}
}

// Route returns the name of the module
func (msg MsgSetDecryptionShare) Route() string { return RouterKey }

// Type returns the action
func (msg MsgSetDecryptionShare) Type() string { return "setDecryptionShare" }

// ValidateBasic runs stateless checks on the message
func (msg MsgSetDecryptionShare) ValidateBasic() sdk.Error {
	if msg.Sender.Empty() {
		return sdk.ErrInvalidAddress("missing key holder address")
	}

	share, err := msg.DecryptionShare.Deserialize()

	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't deserialaize decryption share: %v", err))
	}

	if !share.KeyHolderAddr.Equals(msg.Sender) {
		return sdk.ErrUnauthorized("key holder and sender are not equal")
	}

	return nil
}

// GetSignBytes encodes the message for signing
func (msg MsgSetDecryptionShare) GetSignBytes() []byte {
	return sdk.MustSortJSON(ModuleCdc.MustMarshalJSON(msg))
}

// GetSigners defines whose signature is required
func (msg MsgSetDecryptionShare) GetSigners() []sdk.AccAddress {
	return []sdk.AccAddress{msg.Sender}
}

// MsgSetRandomResult defines result
type MsgSetRandomResult struct {
	Round  uint64         `json:"round"`
	Sender sdk.AccAddress `json:"sender"`
}

// NewMsgSetRandomResult is a constructor for set result
func NewMsgSetRandomResult(round uint64, sender sdk.AccAddress) MsgSetRandomResult {
	return MsgSetRandomResult{
		Round:  round,
		Sender: sender,
	}
}

// Route returns the name of the module
func (msg MsgSetRandomResult) Route() string { return RouterKey }

// Type returns the action
func (msg MsgSetRandomResult) Type() string { return "setRandomResult" }

// ValidateBasic runs stateless checks on the message
func (msg MsgSetRandomResult) ValidateBasic() sdk.Error {
	if msg.Sender.Empty() {
		return sdk.ErrInvalidAddress("missing key holder address")
	}
	return nil
}

// GetSignBytes encodes the message for signing
func (msg MsgSetRandomResult) GetSignBytes() []byte {
	return sdk.MustSortJSON(ModuleCdc.MustMarshalJSON(msg))
}

// GetSigners defines whose signature is required
func (msg MsgSetRandomResult) GetSigners() []sdk.AccAddress {
	return []sdk.AccAddress{msg.Sender}
}
