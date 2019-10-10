package herb

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/store"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/dgamingfoundation/HERB/dkg"
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
	"github.com/dgamingfoundation/HERB/x/herb/types"

	abci "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/libs/log"
	tmtypes "github.com/tendermint/tendermint/types"
	dbm "github.com/tendermint/tm-db"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof"
	"go.dedis.ch/kyber/v3/share"
	kyberenc "go.dedis.ch/kyber/v3/util/encoding"
)

func TestHERB(t *testing.T) {
	n := 10
	trh := 8
	testCases := make([]int, n)
	for i := range testCases {
		testCases[i] = i
	}
	ctx, keeper, _ := Initialize(uint64(trh), uint64(n), uint64(n))
	userAddrs := createTestAddrs(n)
	partKeys, err := setKeyHolders(ctx, &keeper, userAddrs, trh, n)
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
	VerKeysJSON, err := keeper.GetVerificationKeys(ctx)
	if err != nil {
		t.Errorf("can't get verification keys: %v", err)
	}
	Verkeys, err := types.VerificationKeyArrayDeserialize(VerKeysJSON)
	if err != nil {
		t.Errorf("can't decode verification keys")
	}

	for round, r := range testCases {
		var ciphertextShares []types.CiphertextShare
		var ciphertexts []elgamal.Ciphertext
		var decryptionShares []types.DecryptionShare
		var dshares []*share.PubShare
		keeper.forceRoundStage(ctx, uint64(round), stageCtCollecting)
		keeper.forceCurrentRound(ctx, uint64(round))

		for i := 0; i < n; i++ {
			y := keeper.group.Scalar().SetInt64(int64(r))
			rr := keeper.group.Scalar().SetInt64(int64(r + i))
			ct, CE, err := ciphertextTest(P256, commonkey, y, rr)
			if err != nil {
				t.Errorf("failed create proofs: %v", err)
			}
			ctShare := types.CiphertextShare{ct, CE, userAddrs[i]}
			ciphertexts = append(ciphertexts, ctShare.Ciphertext)
			ciphertextShares = append(ciphertextShares, ctShare)
			err1 := keeper.SetCiphertext(ctx, &ctShare)
			if err1 != nil {
				t.Errorf("failed set ciphertext: %v", err1)
			}
		}
		newCiphertexts, err := keeper.GetAllCiphertexts(ctx, uint64(round))
		if err != nil {
			t.Errorf("failed get all ciphertexts: %v", err)
		}
		if len(newCiphertexts) != n {
			t.Errorf("Some ciphertexts weren't added to the store. Sum of ciphertextes: %v", len(newCiphertexts))
		}
		for i := 0; i < n; i++ {
			providerFound := false
			originalProvider := ciphertextShares[i].EntropyProvider
			for _, nCt := range newCiphertexts {
				if nCt.EntropyProvider.Equals(originalProvider) {
					providerFound = true
				}
			}
			if !providerFound {
				t.Errorf("new slice doesn't contains original entropy provider, round: %v, expected: %v", round, ciphertextShares[i].EntropyProvider.String())
			}
			if !newCiphertexts[i].Ciphertext.Equal(ciphertextShares[i].Ciphertext) {
				t.Errorf("ciphertexts don't equal, round: %v", round)
			}
			if !bytes.Equal(newCiphertexts[i].CEproof, ciphertextShares[i].CEproof) {
				t.Errorf("CEproofs don't equal , round  %v", round)
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
		for i := 0; i < trh; i++ {
			ds, dleq, err := elgamal.CreateDecShare(P256, ACiphertext, partKeys[i])
			if err != nil {
				t.Errorf("failed creating decryption share: %v", err)
			}
			decShare := types.DecryptionShare{share.PubShare{I: Verkeys[i].KeyHolderID, V: ds}, dleq, userAddrs[i]}
			decryptionShares = append(decryptionShares, decShare)
			dshares = append(dshares, &share.PubShare{I: Verkeys[i].KeyHolderID, V: ds})
			err = keeper.SetDecryptionShare(ctx, &decShare)
			if err != nil {
				t.Errorf("Can't set decryption shares %v", err)
			}
		}
		newDecryptionShares, err := keeper.GetAllDecryptionShares(ctx, uint64(round))
		if err != nil {
			t.Errorf("Can't get all decryption shares %v", err)
		}
		for i := 0; i < trh; i++ {
			holderFound := false
			originalHolder := decryptionShares[i].KeyHolderAddr
			for _, ds := range newDecryptionShares {
				if ds.KeyHolderAddr.Equals(originalHolder) {
					holderFound = true
				}
			}
			if !holderFound {
				t.Errorf("new map doesn't contains original key holder, round: %v", round)
			}
			if !newDecryptionShares[i].DecShare.V.Equal(decryptionShares[i].DecShare.V) {
				t.Errorf("decryption shares don't equal, round: %v", round)
			}
			if !newDecryptionShares[i].DLEQproof.C.Equal(decryptionShares[i].DLEQproof.C) ||
				!newDecryptionShares[i].DLEQproof.R.Equal(decryptionShares[i].DLEQproof.R) ||
				!newDecryptionShares[i].DLEQproof.VG.Equal(decryptionShares[i].DLEQproof.VG) ||
				!newDecryptionShares[i].DLEQproof.VH.Equal(decryptionShares[i].DLEQproof.VH) {
				t.Errorf("dleq proofs don't equal")
			}
		}
		resultPoint := elgamal.Decrypt(keeper.group, ACiphertext, dshares, n)
		hash := P256.Hash()
		_, err2 := resultPoint.MarshalTo(hash)
		if err2 != nil {
			t.Errorf("failed to marshal result point to hash: %v", err)
		}
		result := hash.Sum(nil)
		newresult, err := keeper.RandomResult(ctx, uint64(round))
		if err != nil {
			t.Errorf("can't get result: %v", err)
		}
		if !bytes.Equal(result, newresult) {
			t.Errorf("results don't equal")
		}
	}
}

func TestSetGetCiphertext(t *testing.T) {
	round := 1
	r := 2
	n := 3
	trh := 3
	ctx, keeper, _ := Initialize(uint64(trh), uint64(n), uint64(n))
	var ciphertextShares []types.CiphertextShare
	userAddrs := createTestAddrs(n)
	keeper.forceRoundStage(ctx, uint64(round), stageCtCollecting)
	keeper.forceCurrentRound(ctx, uint64(round))
	_, err := setKeyHolders(ctx, &keeper, userAddrs, trh, n)
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
	for i := 0; i < n; i++ {
		y := keeper.group.Scalar().SetInt64(int64(r))
		rr := keeper.group.Scalar().SetInt64(int64(r + i))
		ct, CE, err := ciphertextTest(P256, commonkey, y, rr)
		if err != nil {
			t.Errorf("failed create proofs: %v", err)
		}
		ctShare := types.CiphertextShare{Ciphertext: ct, CEproof: CE, EntropyProvider: userAddrs[i]}
		ciphertextShares = append(ciphertextShares, ctShare)
		err1 := keeper.SetCiphertext(ctx, &ctShare)
		if err1 != nil {
			t.Errorf("failed set ciphertext: %v", err1)
		}
	}
	newCiphertexts, err := keeper.GetAllCiphertexts(ctx, uint64(round))
	if err != nil {
		t.Errorf("failed get all ciphertexts: %v", err)
	}
	for i := 0; i < n; i++ {
		if newCiphertexts[i].EntropyProvider.String() != ciphertextShares[i].EntropyProvider.String() {
			t.Errorf("new map doesn't contains original entropy provider, round: %v, expected: %v", round, ciphertextParts[i].EntropyProvider.String())
		}
		if !newCiphertexts[i].Ciphertext.Equal(ciphertextShares[i].Ciphertext) {
			t.Errorf("ciphertexts don't equal, round: %v", round)
		}
	}
}

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

func ciphertextTest(group proof.Suite, commonKey kyber.Point, y kyber.Scalar, r kyber.Scalar) (ct elgamal.Ciphertext, ceProof []byte, err error) {
	m := group.Point().Mul(y, nil)
	s := group.Point().Mul(r, commonKey)
	a := group.Point().Mul(r, nil)
	b := s.Add(group.Point().Mul(r, commonKey), m)
	ct = elgamal.Ciphertext{PointA: a, PointB: b}
	ceProof, err = elgamal.CE(group, group.Point().Base(), commonKey, ct.PointA, ct.PointB, r, y)
	if err != nil {
		return
	}
	return
}

// createTestAddrs creates numAddrs account addresses
func createTestAddrs(numAddrs int) []sdk.AccAddress {
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

func setKeyHolders(ctx sdk.Context, k *Keeper, adds []sdk.AccAddress, t, n int) ([]kyber.Scalar, error) {
	store := ctx.KVStore(k.storeKey)
	keyCommonBytes := []byte(keyCommonKey)
	if store.Has(keyCommonBytes) {
		return nil, sdk.ErrUnknownRequest("Public key already exist")
	}
	decShare, verKeys, err := dkg.RabinDKGSimulator(P256.String(), n, t)
	if err != nil {
		return nil, err
	}
	commonKey := decShare[0].Public()
	commonKeyStr, err := kyberenc.PointToStringHex(P256, commonKey)
	if err != nil {
		return nil, err
	}
	store.Set(keyCommonBytes, []byte(commonKeyStr))
	ListVerKeys := make([]*types.VerificationKey, n)
	for i := 0; i < n; i++ {
		ListVerKeys[i] = &types.VerificationKey{Key: *verKeys[i], KeyHolderID: i, Sender: adds[i]}
	}

	ListVerKeysJSON, err := types.VerificationKeyArraySerialize(ListVerKeys)
	if err != nil {
		return nil, sdk.ErrUnknownRequest("Can't serialize map")
	}
	err = k.SetVerificationKeys(ctx, ListVerKeysJSON)
	if err != nil {
		return nil, err
	}
	err = k.InitializeVerificationKeys(ctx)
	if err != nil {
		panic(err)
	}
	partialKeys := make([]kyber.Scalar, n)
	for i := 0; i < n; i++ {
		partialKeys[i] = decShare[i].PriShare().V
	}

	return partialKeys, nil
}
