package types

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// RouterKey is they name of the herb module
const RouterKey = ModuleName

// MsgSetCiphertextshare defines message for the first HERB phase (collecting ciphertext share)
type MsgSetCiphertextShare struct {
	CiphertextShare CiphertextShareJSON `json:"ciphertext_share"`
	Sender          sdk.AccAddress      `json:"sender"`
}

// NewMsgSetCiphertextShare is a constructor for set ciphertext share message (first HERB phase)
func NewMsgSetCiphertextShare(ctShare CiphertextShareJSON, sender sdk.AccAddress) MsgSetCiphertextShare {
	return MsgSetCiphertextShare{
		CiphertextShare: ctShare,
		Sender:          sender,
	}
}

// Route returns the name of the module
func (msg MsgSetCiphertextShare) Route() string { return RouterKey }

// Type returns the action
func (msg MsgSetCiphertextShare) Type() string { return "setCiphertextShare" }

// ValidateBasic runs stateless checks on the message
func (msg MsgSetCiphertextShare) ValidateBasic() sdk.Error {
	if msg.Sender.Empty() {
		return sdk.ErrInvalidAddress("missing entropy provider address")
	}

	ctShare, err := msg.CiphertextShare.Deserialize()

	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't deserialaize ciphertext: %v", err))
	}

	if !ctShare.EntropyProvider.Equals(msg.Sender) {
		return sdk.ErrUnauthorized("entropy provider and sender are not equal")
	}

	return nil
}

// GetSignBytes encodes the message for signing
func (msg MsgSetCiphertextShare) GetSignBytes() []byte {
	return sdk.MustSortJSON(ModuleCdc.MustMarshalJSON(msg))
}

// GetSigners defines whose signature is required
func (msg MsgSetCiphertextShare) GetSigners() []sdk.AccAddress {
	return []sdk.AccAddress{msg.Sender}
}

// MsgSetCiphertextShare defines message for the first HERB phase (collecting ciphertext share)
type MsgSetDecryptionShare struct {
	DecryptionShare DecryptionShareJSON `json:"decryption_share"`
	Sender          sdk.AccAddress      `json:"sender"`
}

// NewMsgSetCiphertextShare is a constructor for set ciphertext share message (first HERB phase)
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
