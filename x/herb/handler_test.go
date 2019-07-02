package herb

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
	"github.com/dgamingfoundation/HERB/x/herb/types"
	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto/ed25519"
)

func TestHandleSetCiphertext(t *testing.T) {
	ctx, keeper, _ := Initialize()
	userPk1 := ed25519.GenPrivKey().PubKey()
	userAddr1 := sdk.AccAddress(userPk1.Address())
	handler := NewHandler(keeper)
	round := 1
	g1 := keeper.group.Point().Base()
	g2 := keeper.group.Point().Mul(keeper.group.Scalar().SetInt64(5), g1)
	ct := elgamal.Ciphertext{g1, g2}
	ctPart := types.CiphertextPart{ct, []byte("example"), []byte("example3"), userAddr1}
	ctPartJSON, err := types.NewCiphertextPartJSON(&ctPart)
	if err != nil {
		t.Errorf("failed: %v", err)
	}
	setCt := types.NewMsgSetCiphertextPart(uint64(round), *ctPartJSON, userAddr1)
	res := handler(ctx, setCt)
	require.True(t, res.IsOK(), "%v", res)
}
