package herb

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/store"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
	"github.com/dgamingfoundation/HERB/x/herb/types"
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
		userAddrs := CreateTestAddrs(r)
		g1 := keeper.group.Point().Base()
		for i := 0; i < r; i++ {
			g2 := keeper.group.Point().Mul(keeper.group.Scalar().SetInt64(int64(i)), g1)
			ct := elgamal.Ciphertext{g1, g2}
			ctPart := types.CiphertextPart{ct, []byte("example"), []byte("example3"), userAddrs[i]}
			ciphertextParts = append(ciphertextParts, ctPart)
			err := keeper.SetCiphertext(ctx, uint64(round), &ctPart)
			if err != nil {
				t.Errorf("failed set ciphertext: %v", err)
			}
		}
		newCiphertexts, err := keeper.GetAllCiphertexts(ctx, uint64(round))
		if err != nil {
			t.Errorf("failed get all ciphertexts: %v", err)
		}
		for i := 0; i < r; i++ {
			if _, ok := newCiphertexts[ciphertextParts[i].EntropyProvider.String()]; !ok {
				t.Errorf("new map doesn't contains original entropy provider, round: %v", round)
			}
			if !newCiphertexts[ciphertextParts[i].EntropyProvider.String()].Ciphertext.Equal(ciphertextParts[i].Ciphertext) {
				t.Errorf("ciphertexts don't equal, round: %v", round)
			}
		}
	}
}
func TestAggregatedCiphertext(t *testing.T) {
	testCases := []int{1, 5, 10}
	for round, r := range testCases {
		ctx, keeper, _ := Initialize()
		commonCiphertext := elgamal.Ciphertext{keeper.group.Point().Null(), keeper.group.Point().Null()}
		userAddrs := CreateTestAddrs(r)
		g1 := keeper.group.Point().Base()
		for i := 0; i < r; i++ {
			g2 := keeper.group.Point().Mul(keeper.group.Scalar().SetInt64(int64(i)), g1)
			ct := elgamal.Ciphertext{g1, g2}
			commonCiphertext.PointA = keeper.group.Point().Add(commonCiphertext.PointA, ct.PointA)
			commonCiphertext.PointB = keeper.group.Point().Add(commonCiphertext.PointB, ct.PointB)
			ctPart := types.CiphertextPart{ct, []byte("example"), []byte("example3"), userAddrs[i]}
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

// CreateTestAddrs creates numAddrs account addresses
func CreateTestAddrs(numAddrs int) []sdk.AccAddress {
	var addresses []sdk.AccAddress
	var buffer bytes.Buffer

	// start at 100 so we can make up to 999 test addresses with valid test addresses
	for i := 100; i < (numAddrs + 100); i++ {
		numString := strconv.Itoa(i)
		buffer.WriteString("A58856F0FD53BF058B4909A21AEC019107BA6") //base address string

		buffer.WriteString(numString) //adding on final two digits to make addresses unique
		res, _ := sdk.AccAddressFromHex(buffer.String())
		bech := res.String()
		addresses = append(addresses, testAddr(buffer.String(), bech))
		buffer.Reset()
	}
	return addresses
}

// for incode address generation
func testAddr(addr string, bech string) sdk.AccAddress {

	res, err := sdk.AccAddressFromHex(addr)
	if err != nil {
		panic(err)
	}
	bechexpected := res.String()
	if bech != bechexpected {
		panic("Bech encoding doesn't match reference")
	}

	bechres, err := sdk.AccAddressFromBech32(bech)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(bechres, res) {
		panic("Bech decode and hex decode don't match")
	}

	return res
}

func TestSetGetDecryptionShare(t *testing.T) {
	testCases := []int{1, 5, 10}
	for round, r := range testCases {
		var decryptionShares []types.DecryptionShare
		ctx, keeper, _ := Initialize()
		userAddrs := CreateTestAddrs(r)
		g := keeper.group.Point().Base()
		for i := 0; i < r; i++ {
			x := keeper.group.Scalar().SetInt64(int64(i))
			g1 := keeper.group.Point().Mul(x, g)
			g2 := keeper.group.Point().Mul(x, g1)
			dleProof, _, _, err := elgamal.DLE(P256, g1, g2, x)
			if err != nil {
				t.Errorf("Dle proof doesn't created")
			}
			decShare := types.DecryptionShare{g2, dleProof, userAddrs[i]}
			decryptionShares = append(decryptionShares, decShare)
			err1 := keeper.SetDecryptionShare(ctx, uint64(round), &decShare)
			if err1 != nil {
				t.Errorf("failed set decryption share: %v", err1)
			}
		}
		newDecryptionShares, err := keeper.GetAllDecryptionShares(ctx, uint64(round))
		if err != nil {
			t.Errorf("failed get all decryption shares: %v", err)
		}
		for i := 0; i < r; i++ {
			if _, ok := newDecryptionShares[decryptionShares[i].KeyHolder.String()]; !ok {
				t.Errorf("new map doesn't contains original key holder, round: %v", round)
			}
			if !newDecryptionShares[decryptionShares[i].KeyHolder.String()].DecShare.Equal(decryptionShares[i].DecShare) {
				t.Errorf("ciphertexts don't equal, round: %v", round)
			}
			if !newDecryptionShares[decryptionShares[i].KeyHolder.String()].DLEproof.C.Equal(decryptionShares[i].DLEproof.C) ||
				!newDecryptionShares[decryptionShares[i].KeyHolder.String()].DLEproof.R.Equal(decryptionShares[i].DLEproof.R) ||
				!newDecryptionShares[decryptionShares[i].KeyHolder.String()].DLEproof.VG.Equal(decryptionShares[i].DLEproof.VG) ||
				!newDecryptionShares[decryptionShares[i].KeyHolder.String()].DLEproof.VH.Equal(decryptionShares[i].DLEproof.VH) {
				t.Errorf("dle proofs don't equal")
			}
		}
	}
}
