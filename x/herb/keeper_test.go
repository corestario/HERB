package herb

import (
	"bytes"
	"strconv"
	"testing"

	"go.dedis.ch/kyber/v3"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/store"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
	"github.com/dgamingfoundation/HERB/x/herb/types"
	abci "github.com/tendermint/tendermint/abci/types"
	dbm "github.com/tendermint/tendermint/libs/db"
	"github.com/tendermint/tendermint/libs/log"
	tmtypes "github.com/tendermint/tendermint/types"
	"go.dedis.ch/kyber/v3/proof"
	"go.dedis.ch/kyber/v3/share"
	kyberenc "go.dedis.ch/kyber/v3/util/encoding"
)

func Initialize(thresholdDecryption uint64, thresholdParts uint64, n uint64) (ctx sdk.Context, keeperInstance Keeper, cdc *codec.Codec) {
	cdc = codec.New()
	types.RegisterCodec(cdc)
	codec.RegisterCrypto(cdc)
	keyHERB := sdk.NewKVStoreKey(types.StoreKey)
	keyCt := sdk.NewKVStoreKey(types.CtStoreKey)
	keyDs := sdk.NewKVStoreKey(types.DsStoreKey)
	keeperInstance = NewKeeper(keyHERB, keyCt, keyDs, cdc)
	db := dbm.NewMemDB()
	ms := store.NewCommitMultiStore(db)
	ms.MountStoreWithDB(keyHERB, sdk.StoreTypeIAVL, db)
	ms.MountStoreWithDB(keyCt, sdk.StoreTypeIAVL, db)
	ms.MountStoreWithDB(keyDs, sdk.StoreTypeIAVL, db)
	err := ms.LoadLatestVersion()
	if err != nil {
		panic(err)
	}
	ctx = sdk.NewContext(ms, abci.Header{ChainID: "test-chain"}, true, log.NewNopLogger())
	keeperInstance.SetKeyHoldersNumber(ctx, n)
	keeperInstance.SetThreshold(ctx, thresholdParts, thresholdDecryption)
	ctx = ctx.WithConsensusParams(
		&abci.ConsensusParams{
			Validator: &abci.ValidatorParams{
				PubKeyTypes: []string{tmtypes.ABCIPubKeyTypeEd25519},
			},
		},
	)
	return
}

func CiphertextTest(group proof.Suite, commonKey kyber.Point, y kyber.Scalar, r kyber.Scalar) (ct elgamal.Ciphertext, DLKproof []byte, RKproof []byte, err error) {
	M := group.Point().Mul(y, nil)
	S := group.Point().Mul(r, commonKey)
	A := group.Point().Mul(r, nil)
	B := S.Add(group.Point().Mul(r, commonKey), M)
	ct = elgamal.Ciphertext{A, B}
	DLKproof, err = elgamal.DLK(group, group.Point().Base(), r, ct.PointA)
	if err != nil {
		return
	}
	RKproof, err = elgamal.RK(group, group.Point().Base(), y, commonKey, r, ct.PointB)
	return
}

func TestSetGetCiphertext(t *testing.T) {
	testCases := []int{1, 2}
	l := 3
	for round, r := range testCases {
		var ciphertextParts []types.CiphertextPart
		ctx, keeper, _ := Initialize(uint64(l), uint64(l), uint64(l))
		userAddrs := CreateTestAddrs(l)
		keeper.forceRoundStage(ctx, uint64(round), stageCtCollecting)
		keeper.forceCurrentRound(ctx, uint64(round))
		err := SetKeyHolders(ctx, keeper, userAddrs)
		if err != nil {
			t.Errorf("can't set public key %v", err)
		}
		store := ctx.KVStore(keeper.storeKey)
		keyCommonBytes := []byte(keyCommonKey)
		if !store.Has(keyCommonBytes) {
			t.Errorf("Public key isn't exist")
		}
		commonkeyBytes := store.Get(keyCommonBytes)
		commonkeyStr := string(commonkeyBytes)
		commonkey, err := kyberenc.StringHexToPoint(keeper.group, commonkeyStr)
		if err != nil {
			t.Errorf("can't decode common key to point")
		}
		for i := 0; i < l; i++ {
			y := keeper.group.Scalar().SetInt64(int64(r))
			rr := keeper.group.Scalar().SetInt64(int64(r + i))
			ct, DLK, RK, err := CiphertextTest(P256, commonkey, y, rr)
			if err != nil {
				t.Errorf("failed create proofs: %v", err)
			}
			ctPart := types.CiphertextPart{ct, DLK, RK, userAddrs[i]}
			ciphertextParts = append(ciphertextParts, ctPart)
			err1 := keeper.SetCiphertext(ctx, &ctPart)
			if err1 != nil {
				t.Errorf("failed set ciphertext: %v", err1)
			}
		}
		newCiphertexts, err := keeper.GetAllCiphertexts(ctx, uint64(round))
		if err != nil {
			t.Errorf("failed get all ciphertexts: %v", err)
		}
		for i := 0; i < l; i++ {
			if _, ok := newCiphertexts[ciphertextParts[i].EntropyProvider.String()]; !ok {
				t.Errorf("new map doesn't contains original entropy provider, round: %v, expected: %v", round, ciphertextParts[i].EntropyProvider.String())
			}
			if !newCiphertexts[ciphertextParts[i].EntropyProvider.String()].Ciphertext.Equal(ciphertextParts[i].Ciphertext) {
				t.Errorf("ciphertexts don't equal, round: %v", round)
			}
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

/*func TestSetGetDecryptionShare(t *testing.T) {
	testCases := []int{1, 5, 10}
	l := 3
	for round, r := range testCases {
		var decryptionShares []types.DecryptionShare
		ctx, keeper, _ := Initialize(uint64(l), uint64(l), uint64(l))
		userAddrs := CreateTestAddrs(l)
		keeper.forceRoundStage(ctx, uint64(round), stageDSCollecting)
		keeper.forceCurrentRound(ctx, uint64(round))
		g := keeper.group.Point().Base()
		for i := 0; i < l; i++ {
			x := keeper.group.Scalar().SetInt64(int64(r))
			g1 := keeper.group.Point().Mul(x, g)
			g2 := keeper.group.Point().Mul(x, g1)
			dleProof, _, _, err := elgamal.DLE(P256, g1, g2, x)
			if err != nil {
				t.Errorf("Dle proof doesn't created")
			}
			decShare := types.DecryptionShare{share.PubShare{i, g2}, dleProof, userAddrs[i]}
			decryptionShares = append(decryptionShares, decShare)
			err1 := keeper.SetDecryptionShare(ctx, &decShare)
			if err1 != nil {
				t.Errorf("failed set decryption share: %v", err1)
			}
		}
		newDecryptionShares, err := keeper.GetAllDecryptionShares(ctx, uint64(round))
		if err != nil {
			t.Errorf("failed get all decryption shares: %v", err)
		}
		for i := 0; i < r; i++ {
			if _, ok := newDecryptionShares[decryptionShares[i].KeyHolderAddr.String()]; !ok {
				t.Errorf("new map doesn't contains original key holder, round: %v", round)
			}
			if !newDecryptionShares[decryptionShares[i].KeyHolderAddr.String()].DecShare.V.Equal(decryptionShares[i].DecShare.V) {
				t.Errorf("ciphertexts don't equal, round: %v", round)
			}
			if !newDecryptionShares[decryptionShares[i].KeyHolderAddr.String()].DLEproof.C.Equal(decryptionShares[i].DLEproof.C) ||
				!newDecryptionShares[decryptionShares[i].KeyHolderAddr.String()].DLEproof.R.Equal(decryptionShares[i].DLEproof.R) ||
				!newDecryptionShares[decryptionShares[i].KeyHolderAddr.String()].DLEproof.VG.Equal(decryptionShares[i].DLEproof.VG) ||
				!newDecryptionShares[decryptionShares[i].KeyHolderAddr.String()].DLEproof.VH.Equal(decryptionShares[i].DLEproof.VH) {
				t.Errorf("dle proofs don't equal")
			}
		}
	}
}*/

func SetKeyHolders(ctx sdk.Context, k Keeper, adds []sdk.AccAddress) error {
	store := ctx.KVStore(k.storeKey)
	keyCommonBytes := []byte(keyCommonKey)
	if store.Has(keyCommonBytes) {
		return sdk.ErrUnknownRequest("Public key already exist")
	}
	commonKeyStr := "0452b4a6d7883102258a87539c41898cd1c78bcc27dd905d9111e8b066504ba31b160580530886a2200833c2281e10377dbb2007abc531959a23df365ffc16ee18"
	commonkey := []byte(commonKeyStr)
	store.Set(keyCommonBytes, commonkey)
	VKstr := []string{"041ea050368a68a13a12f1026870b997d6d15d74a59f243ef9c38aea5089387f13dd754344b73ab5d59a716a13abcf4cc3767b723a60d1c367dde5b52d3b04781f",
		"04711451d30356c470e156941119d44cd4e8b44f04497c1875be584c93d423405e96f8fe4efb8c7d181bdea18b2ba1673f0d639eba187e491ae00d25320711f9f5",
		"04e90f797b084978e896f398dd408249d72218803f155044c994c4f4ac7da57db44e00771ecec98e3a213a9e141e678700011d923ab768d5d329916c611dea85cf"}
	id := []int{0, 1, 2}
	VK := make([]kyber.Point, len(id))
	var err error
	MapVerKeys := make(map[string]*types.VerificationKey)
	for i := 0; i < len(id); i++ {
		VK[i], err = kyberenc.StringHexToPoint(k.group, VKstr[i])
		if err != nil {
			return sdk.ErrUnknownRequest("Can't decode point from string")
		}
		MapVerKeys[adds[i].String()] = &types.VerificationKey{VK[i], id[i]}
	}

	MapVerKeysJSON, err := types.VerificationKeyMapSerialize(MapVerKeys)
	if err != nil {
		return sdk.ErrUnknownRequest("Can't serialize map")
	}
	MapVerKeysBytes, err4 := k.cdc.MarshalJSON(MapVerKeysJSON)
	if err4 != nil {
		return sdk.ErrUnknownRequest("Can't marschal map")
	}
	keyVerKeysBytes := []byte(keyVerificationKeys)
	if store.Has(keyVerKeysBytes) {
		return sdk.ErrUnknownRequest("Verification keys already exist")
	}
	store.Set(keyVerKeysBytes, MapVerKeysBytes)
	return nil
}

func TestHERB(t *testing.T) {
	testCases := []int{1}
	l := 3
	ctx, keeper, _ := Initialize(uint64(l), uint64(l), uint64(l))
	userAddrs := CreateTestAddrs(l)
	err := SetKeyHolders(ctx, keeper, userAddrs)
	if err != nil {
		t.Errorf("can't set public key and verification keys %v", err)
	}
	store := ctx.KVStore(keeper.storeKey)
	keyCommonBytes := []byte(keyCommonKey)
	if !store.Has(keyCommonBytes) {
		t.Errorf("Public key isn't exist")
	}
	commonkeyBytes := store.Get(keyCommonBytes)
	commonkeyStr := string(commonkeyBytes)
	commonkey, err := kyberenc.StringHexToPoint(keeper.group, commonkeyStr)
	if err != nil {
		t.Errorf("can't decode common key to point")
	}
	keyVerKeysBytes := []byte(keyVerificationKeys)
	if !store.Has(keyVerKeysBytes) {
		t.Errorf("Verification keys don't exist")
	}
	VerKeysBytes := store.Get(keyVerKeysBytes)
	VerKeysJSON := make(map[string]*types.VerificationKeyJSON)
	err1 := keeper.cdc.UnmarshalJSON(VerKeysBytes, &VerKeysJSON)
	if err1 != nil {
		t.Errorf("can't unmarshal verification keys: %v", err1)
	}
	Verkeys, err := types.VerificationKeyMapDeserialize(VerKeysJSON)
	if err != nil {
		t.Errorf("can't decode verification keys")
	}
	partkeys := make([]kyber.Scalar, l)
	pk := []string{"96dd785ef52a85b516f3358fb317572b67f743a97d0c2a164660d134f7af6466",
		"ec0d090634508f2633381696dcd628567d51cee08b73a360e461e49b4c773130",
		"413c99ae737698964f7cf79e0694f981d5c55f69f2c37e268ea92d3ea4dbd8a9"}
	for i := 0; i < l; i++ {
		partkeys[i], err = kyberenc.StringHexToScalar(keeper.group, pk[i])
		if err != nil {
			t.Errorf("can't decode scalar from string ")
		}
	}

	for round, r := range testCases {
		var ciphertextParts []types.CiphertextPart
		var ciphertexts []elgamal.Ciphertext
		var decryptionShares []types.DecryptionShare
		var dshares []*share.PubShare
		keeper.forceRoundStage(ctx, uint64(round), stageCtCollecting)
		keeper.forceCurrentRound(ctx, uint64(round))

		for i := 0; i < l; i++ {
			y := keeper.group.Scalar().SetInt64(int64(r))
			rr := keeper.group.Scalar().SetInt64(int64(r + i))
			ct, DLK, RK, err := CiphertextTest(P256, commonkey, y, rr)
			if err != nil {
				t.Errorf("failed create proofs: %v", err)
			}
			ctPart := types.CiphertextPart{ct, DLK, RK, userAddrs[i]}
			ciphertexts = append(ciphertexts, ctPart.Ciphertext)
			ciphertextParts = append(ciphertextParts, ctPart)
			err1 := keeper.SetCiphertext(ctx, &ctPart)
			if err1 != nil {
				t.Errorf("failed set ciphertext: %v", err1)
			}
		}
		newCiphertexts, err := keeper.GetAllCiphertexts(ctx, uint64(round))
		if err != nil {
			t.Errorf("failed get all ciphertexts: %v", err)
		}
		for i := 0; i < l; i++ {
			if _, ok := newCiphertexts[ciphertextParts[i].EntropyProvider.String()]; !ok {
				t.Errorf("new map doesn't contains original entropy provider, round: %v, expected: %v", round, ciphertextParts[i].EntropyProvider.String())
			}
			if !newCiphertexts[ciphertextParts[i].EntropyProvider.String()].Ciphertext.Equal(ciphertextParts[i].Ciphertext) {
				t.Errorf("ciphertexts don't equal, round: %v", round)
			}
			if !bytes.Equal(newCiphertexts[ciphertextParts[i].EntropyProvider.String()].DLKproof, ciphertextParts[i].DLKproof) {
				t.Errorf("DLKproofs don't equal , round  %v", round)
			}
			if !bytes.Equal(newCiphertexts[ciphertextParts[i].EntropyProvider.String()].RKproof, ciphertextParts[i].RKproof) {
				t.Errorf("DLKproofs don't equal , round  %v", round)
			}
		}
		ACiphertext := elgamal.AggregateCiphertext(keeper.group, ciphertexts)
		newACiphertext, err := keeper.GetAggregatedCiphertext(ctx, uint64(round))
		if err != nil {
			t.Errorf("can't get aggregated ciphertext from store %v", err)
		}
		if !ACiphertext.Equal(*newACiphertext) {
			t.Errorf("aggregated ciphertexts don't equal")
		}
		keeper.forceRoundStage(ctx, uint64(round), stageDSCollecting)
		for i := 0; i < l; i++ {
			ds, dle, err := elgamal.CreateDecShare(P256, ACiphertext, partkeys[i])
			decShare := types.DecryptionShare{share.PubShare{I: Verkeys[userAddrs[i].String()].KeyHolder, V: ds}, dle, userAddrs[i]}
			decryptionShares = append(decryptionShares, decShare)
			dshares = append(dshares, &share.PubShare{I: Verkeys[userAddrs[i].String()].KeyHolder, V: ds})
			err = keeper.SetDecryptionShare(ctx, &decShare)
			if err != nil {
				t.Errorf("Can't set decryption shares %v", err)
			}
		}
		newDecryptionShares, err := keeper.GetAllDecryptionShares(ctx, uint64(round))
		if err != nil {
			t.Errorf("Can't get all decryption shares %v", err)
		}
		for i := 0; i < l; i++ {
			if _, ok := newDecryptionShares[decryptionShares[i].KeyHolder.String()]; !ok {
				t.Errorf("new map doesn't contains original key holder, round: %v", round)
			}
			if !newDecryptionShares[decryptionShares[i].KeyHolder.String()].DecShare.V.Equal(decryptionShares[i].DecShare.V) {
				t.Errorf("ciphertexts don't equal, round: %v", round)
			}
			if !newDecryptionShares[decryptionShares[i].KeyHolder.String()].DLEproof.C.Equal(decryptionShares[i].DLEproof.C) ||
				!newDecryptionShares[decryptionShares[i].KeyHolder.String()].DLEproof.R.Equal(decryptionShares[i].DLEproof.R) ||
				!newDecryptionShares[decryptionShares[i].KeyHolder.String()].DLEproof.VG.Equal(decryptionShares[i].DLEproof.VG) ||
				!newDecryptionShares[decryptionShares[i].KeyHolder.String()].DLEproof.VH.Equal(decryptionShares[i].DLEproof.VH) {
				t.Errorf("dle proofs don't equal")
			}
		}
		resultPoint := elgamal.Decrypt(keeper.group, ACiphertext, dshares, l)
		hash := P256.Hash()
		_, err2 := resultPoint.MarshalTo(hash)
		if err2 != nil {
			t.Errorf("failed to marshal result point to hash: %v", err)
		}
		result := hash.Sum(nil)
		newresult, err := keeper.GetRandom(ctx, uint64(round))
		if err != nil {
			t.Errorf("can't get result: %v", err)
		}
		if !bytes.Equal(result, newresult) {
			t.Errorf("results don't equal")
		}
	}
}
