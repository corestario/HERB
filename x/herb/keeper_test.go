package herb

import (
	"testing"

	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
	"github.com/dgamingfoundation/HERB/x/herb/types"
	"github.com/tendermint/tendermint/crypto/ed25519"
	"github.com/cosmos/cosmos-sdk/store"
	abci "github.com/tendermint/tendermint/abci/types"
	dbm "github.com/tendermint/tendermint/libs/db"
	"github.com/tendermint/tendermint/libs/log"
	tmtypes "github.com/tendermint/tendermint/types"
)

func Initialize() (ctx sdk.Context, keeperInstance Keeper, cdc *codec.Codec) {
	cdc = codec.New()
	types.RegisterCodec(cdc)
	codec.RegisterCrypto(cdc)
	keyHERB := sdk.NewKVStoreKey(types.StoreKey)
	keeperInstance = NewKeeper(keyHERB, cdc)
	db := dbm.NewMemDB()
	ms := store.NewCommitMultiStore(db)
	ms.MountStoreWithDB(keyHERB, sdk.StoreTypeIAVL, db)
	err := ms.LoadLatestVersion()
	if err != nil {
		panic(err)
	}
	ctx = sdk.NewContext(ms, abci.Header{ChainID: "test-chain"}, true, log.NewNopLogger())
	ctx = ctx.WithConsensusParams(
		&abci.ConsensusParams{
			Validator: &abci.ValidatorParams{
				PubKeyTypes: []string{tmtypes.ABCIPubKeyTypeEd25519},
			},
		},
	)
	return
}

func TestSetGetCiphertext(t *testing.T) {
	testCases := []int{1, 5, 10}
	for round, r := range testCases {
		var ciphertextParts []types.CiphertextPart
		ctx, keeper, _ := Initialize()
		userPk1 := ed25519.GenPrivKey().PubKey()
		userAddr1 := sdk.AccAddress(userPk1.Address())
		g1 := keeper.group.Point().Base()
		for i := 0; i < r; i++ {
			g2 := keeper.group.Point().Mul(keeper.group.Scalar().SetInt64(int64(i)), g1)
			ct := elgamal.Ciphertext{g1, g2}
			ctPart := types.CiphertextPart{ct, userAddr1}
			ciphertextParts = append(ciphertextParts, ctPart)
			err := keeper.SetCiphertext(ctx, uint64(round), &ctPart)
			if err != nil {
				t.Errorf("failed set ciphertext: %v", err)
			}
		}
		newciphertextParts, err := keeper.GetAllCiphertext(ctx, uint64(round))
		if err != nil {
			t.Errorf("failed get all ciphertexts: %v", err)
		}
		for i := 0; i < r; i++ {
			if !newciphertextParts[i].EntropyProvider.Equals(ciphertextParts[i].EntropyProvider) {
				t.Errorf("addresses don't equal")
			}
			if !newciphertextParts[i].Ciphertext.Equal(ciphertextParts[i].Ciphertext) {
				t.Errorf("ciphertexts don't equal")
			}
		}
	}
}
func TestAggregatedCiphertext(t *testing.T) {
	testCases := []int{1, 5, 10}
	for round, r := range testCases {
		ctx, keeper, _ := Initialize()
		commonCiphertext := elgamal.Ciphertext{keeper.group.Point().Null(), keeper.group.Point().Null()}
		userPk1 := ed25519.GenPrivKey().PubKey()
		userAddr1 := sdk.AccAddress(userPk1.Address())
		g1 := keeper.group.Point().Base()
		for i := 0; i < r; i++ {
			g2 := keeper.group.Point().Mul(keeper.group.Scalar().SetInt64(int64(i)), g1)
			ct := elgamal.Ciphertext{g1, g2}
			commonCiphertext.PointA = keeper.group.Point().Add(commonCiphertext.PointA, ct.PointA)
			commonCiphertext.PointB = keeper.group.Point().Add(commonCiphertext.PointB, ct.PointB)
			ctPart := types.CiphertextPart{ct, userAddr1}
			err := keeper.SetCiphertext(ctx, uint64(round), &ctPart)
			if err != nil {
				t.Errorf("failed set ciphertext: %v", err)
			}
		}
		newCommonCiphertext, err := keeper.GetAggregatedCiphertext(ctx, uint64(round))
		if err != nil {
			t.Errorf("failed get aggregated ciphertext: %v", err)
		}
		if !commonCiphertext.Equal(*newCommonCiphertext) {
			t.Errorf("ciphertexts don't equal")
		}
	}
}
