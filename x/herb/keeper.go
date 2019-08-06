package herb

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
	"github.com/dgamingfoundation/HERB/x/herb/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
)

// Keeper maintains the link to data storage and exposes methods for the HERB protocol actions
type Keeper struct {
	storeKey                 sdk.StoreKey
	group                    kyber.Group
	storeCiphertextPartsKey  *sdk.KVStoreKey
	storeDecryptionSharesKey *sdk.KVStoreKey
	storeRandomResultsKey    *sdk.KVStoreKey
	cdc                      *codec.Codec
	randmetric               *Metrics
	resTime                  time.Time
}

// NewKeeper creates new instances of the HERB Keeper
func NewKeeper(storeKey sdk.StoreKey, storeCiphertextParts *sdk.KVStoreKey, storeDecryptionShares *sdk.KVStoreKey, storeRandomResults *sdk.KVStoreKey, cdc *codec.Codec) Keeper {
	randmetric := PrometheusMetrics()
	t := time.Now().UTC()
	return Keeper{
		storeKey:                 storeKey,
		group:                    P256,
		storeCiphertextPartsKey:  storeCiphertextParts,
		storeDecryptionSharesKey: storeDecryptionShares,
		storeRandomResultsKey:    storeRandomResults,
		cdc:                      cdc,
		randmetric:               randmetric,
		resTime:                  t,
	}
}

// SetCiphertext store the ciphertext from the entropyProvider to the kv-store
func (k *Keeper) SetCiphertext(ctx sdk.Context, ctPart *types.CiphertextPart) sdk.Error {
	if ctPart.EntropyProvider.Empty() {
		return sdk.ErrInvalidAddress("Entropy provider can't be empty!")
	}
	err := elgamal.DLKVerify(P256, ctPart.Ciphertext.PointA, k.group.Point().Base(), ctPart.DLKproof)
	if err != nil {
		return sdk.ErrUnknownRequest("DLK proof isn't correct")
	}
	round := k.CurrentRound(ctx)
	stage := k.GetStage(ctx, round)
	pubKey, err2 := k.GetCommonPublicKey(ctx)
	if err2 != nil {
		return err2
	}
	err = elgamal.RKVerify(P256, ctPart.Ciphertext.PointB, k.group.Point().Base(), pubKey, ctPart.RKproof)
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("RK proof isn't correct: %v", err))
	}

	if k.CurrentRound(ctx) == 0 && stage == stageUnstarted {
		stage = stageCtCollecting
		k.setStage(ctx, round, stage)
	}

	if stage != stageCtCollecting {
		return sdk.ErrUnknownRequest(fmt.Sprintf("round is not on the ciphertext collecting stage. Current stage: %v", stage))
	}
	ctStore := ctx.KVStore(k.storeCiphertextPartsKey)
	keyBytesAllCt := make([]byte, 8)
	binary.LittleEndian.PutUint64(keyBytesAllCt, round)
	t, err2 := k.GetThresholdParts(ctx)
	if err2 != nil {
		return err2
	}

	var addrList []string
	if ctStore.Has(keyBytesAllCt) {
		addrListBytes := ctStore.Get(keyBytesAllCt)
		err := k.cdc.UnmarshalJSON(addrListBytes, &addrList)
		if err != nil {
			return sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarshal list of all addresses from the store: %v", err))
		}
	}
	addrList = append(addrList, ctPart.EntropyProvider.String())
	newAddrListBytes, err := k.cdc.MarshalJSON(addrList)
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't marshal list of all addresses: %v", err))
	}

	keyBytesCt := createKeyForAddr(round, ctPart.EntropyProvider)
	if ctStore.Has(keyBytesCt) {
		return sdk.ErrInvalidAddress("entropy provider has already send ciphertext part")
	}
	ctJSON, err := types.NewCiphertextPartJSON(ctPart)
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't serialize ctPart: %v", err))
	}
	ctBytes, err := k.cdc.MarshalJSON(ctJSON)
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't marshall ctPart: %v", err))
	}

	ctStore.Set(keyBytesCt, ctBytes)
	ctStore.Set(keyBytesAllCt, newAddrListBytes)

	if uint64(len(addrList)) >= t {
		err2 = k.computeAggregatedCiphertext(ctx, round)
		if err2 != nil {
			return err2
		}
		k.setStage(ctx, round, stageDSCollecting)
	}
	return nil
}

// SetDecryptionShare stores decryption share for the current round
func (k *Keeper) SetDecryptionShare(ctx sdk.Context, ds *types.DecryptionShare) sdk.Error {
	if ds.KeyHolder.Empty() {
		return sdk.ErrInvalidAddress("Key Holder can't be empty!")
	}

	round := k.CurrentRound(ctx)
	stage := k.GetStage(ctx, round)
	if stage != stageDSCollecting {
		return sdk.ErrUnknownRequest(fmt.Sprintf("wrong round stage: %v. round: %v", stage, round))
	}
	aggCiphertext, err := k.GetAggregatedCiphertext(ctx, round)
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't get aggregated ciphertext: %v", err))
	}

	verificationKeysJSON, err := k.GetVerificationKeys(ctx)
	if err != nil {
		return err
	}
	verificationKeys, err := types.VerificationKeyArrayDeserialize(verificationKeysJSON)
	if err != nil {
		return err
	}
	var vkOwner *types.VerificationKey
	for _, verKey := range verificationKeys {
		if verKey.Sender.String() == ds.KeyHolder.String() {
			vkOwner = verKey
		}
	}
	if vkOwner == nil {
		return sdk.ErrUnknownRequest("verification key isn't exist")
	}

	err2 := elgamal.DLEVerify(P256, ds.DLEproof, k.group.Point().Base(), aggCiphertext.PointA, vkOwner.Key, ds.DecShare.V)
	if err2 != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("DLE proof isn't correct: %v", err2))
	}

	dsStore := ctx.KVStore(k.storeDecryptionSharesKey)
	keyBytes := createKeyForAddr(round, vkOwner.Sender)
	keyAllShares := make([]byte, 8)
	binary.LittleEndian.PutUint64(keyAllShares, round)

	var addrList []string
	if dsStore.Has(keyAllShares) {
		addrListBytes := dsStore.Get(keyAllShares)
		err2 := k.cdc.UnmarshalJSON(addrListBytes, &addrList)
		if err2 != nil {
			return sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarshal list of all addresses from the store: %v", err2))
		}
	}
	addrList = append(addrList, ds.KeyHolder.String())
	newAddrListBytes, err2 := k.cdc.MarshalJSON(addrList)
	if err2 != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't marshal list of all addresses: %v", err2))
	}

	if dsStore.Has(keyBytes) {
		return sdk.ErrInvalidAddress("key holder has already send decryption share")
	}
	dsJSON, err := types.NewDecryptionShareJSON(ds)
	if err != nil {
		return err
	}
	dsBytes, err2 := k.cdc.MarshalJSON(dsJSON)
	if err2 != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't marshall decryption share: %v", err2))
	}

	dsStore.Set(keyBytes, dsBytes)
	dsStore.Set(keyAllShares, newAddrListBytes)

	t, err := k.GetThresholdDecryption(ctx)
	if err != nil {
		return err
	}

	if uint64(len(addrList)) >= t {
		err = k.computeRandomResult(ctx, round)
		if err != nil {
			return err
		}
		k.setStage(ctx, round, stageCompleted)
		k.increaseCurrentRound(ctx)
		k.setStage(ctx, k.CurrentRound(ctx), stageCtCollecting)
	}

	return nil
}

// CurrentRound returns current generation round as uint64
func (k *Keeper) CurrentRound(ctx sdk.Context) uint64 {
	store := ctx.KVStore(k.storeKey)
	keyBytes := []byte(keyCurrentRound)
	if !store.Has(keyBytes) {
		roundBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(roundBytes, 0)
		store.Set(keyBytes, roundBytes)
		return 0
	} else {
		roundBytes := store.Get(keyBytes)
		round := binary.LittleEndian.Uint64(roundBytes)
		return round
	}
}

// increaseCurrentRound increments current round
func (k *Keeper) increaseCurrentRound(ctx sdk.Context) {
	currentRound := k.CurrentRound(ctx)
	currentRound = currentRound + 1

	store := ctx.KVStore(k.storeKey)

	roundBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(roundBytes, currentRound)
	store.Set([]byte(keyCurrentRound), roundBytes)
}

// GetAllCiphertexts returns all ciphertext parts for the given round as go-slice
func (k *Keeper) GetAllCiphertexts(ctx sdk.Context, round uint64) ([]*types.CiphertextPart, sdk.Error) {
	ctStore := ctx.KVStore(k.storeCiphertextPartsKey)
	stage := k.GetStage(ctx, round)

	if stage == stageUnstarted {
		return nil, sdk.ErrUnknownRequest("round hasn't started yet")
	}

	keyBytesAllCt := make([]byte, 8)
	binary.LittleEndian.PutUint64(keyBytesAllCt, round)

	//if store doesn't have such key -> no cts was added
	if !ctStore.Has(keyBytesAllCt) {
		return []*types.CiphertextPart{}, nil
	}

	addrListBytes := ctStore.Get(keyBytesAllCt)
	var addrList []string
	err := k.cdc.UnmarshalJSON(addrListBytes, &addrList)
	if err != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarshal list of all adderesses from store: %v", err))
	}
	ctList := make([]*types.CiphertextPart, 0, len(addrList))
	for _, addrStr := range addrList {
		addr, err := sdk.AccAddressFromBech32(addrStr)
		if err != nil {
			return nil, sdk.ErrUnknownAddress(fmt.Sprintf("can't get address from bench32: %v", err))
		}
		key := createKeyForAddr(round, addr)
		if !ctStore.Has(key) {
			return nil, sdk.ErrUnknownRequest("addresses list and real ciphertext providers doesn't meet")
		}
		ctBytes := ctStore.Get(key)
		var ctJSON types.CiphertextPartJSON
		err = k.cdc.UnmarshalJSON(ctBytes, &ctJSON)
		if err != nil {
			return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarthsal ciphertext: %v", err))
		}
		ct, err2 := ctJSON.Deserialize()
		if err2 != nil {
			return nil, err2
		}
		ctList = append(ctList, ct)
	}
	return ctList, nil
}

// GetAggregatedCiphertext aggregate all sended ciphertext parts in one ciphertext and returns it
func (k *Keeper) GetAggregatedCiphertext(ctx sdk.Context, round uint64) (*elgamal.Ciphertext, sdk.Error) {

	stage := k.GetStage(ctx, round)
	if stage != stageDSCollecting && stage != stageCompleted {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("wrong round stage: %v. round: %v", stage, round))
	}

	store := ctx.KVStore(k.storeKey)
	keyBytes := createKeyBytesByRound(round, keyAggregatedCiphertext)
	if !store.Has(keyBytes) {
		return nil, sdk.ErrInternal("There is not aggregated ciphertext in the store")
	}

	result := store.Get(keyBytes)
	var newaCtSer *elgamal.CiphertextJSON
	err := k.cdc.UnmarshalJSON(result, &newaCtSer)
	if err != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarshal aggregated ciphertext: %v", err))
	}
	newCt, err := newaCtSer.Deserialize(P256)
	if err != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't deserialize aggregated ciphertext: %v", err))
	}
	return newCt, nil
}

// GetAllDecryptionShares returns all decryption shares for the given round
func (k *Keeper) GetAllDecryptionShares(ctx sdk.Context, round uint64) ([]*types.DecryptionShare, sdk.Error) {
	stage := k.GetStage(ctx, round)
	if stage != stageDSCollecting && stage != stageCompleted {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("wrong round stage: %v. round: %v", stage, round))
	}

	dsStore := ctx.KVStore(k.storeDecryptionSharesKey)

	keyAllShares := make([]byte, 8)
	binary.LittleEndian.PutUint64(keyAllShares, round)

	if !dsStore.Has(keyAllShares) {
		return []*types.DecryptionShare{}, nil
	}

	addrListBytes := dsStore.Get(keyAllShares)
	var addrList []string
	err := k.cdc.UnmarshalJSON(addrListBytes, &addrList)
	if err != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarshal list of all adderesses from store: %v", err))
	}
	dsList := make([]*types.DecryptionShare, 0, len(addrList))
	for _, addrStr := range addrList {
		addr, err := sdk.AccAddressFromBech32(addrStr)
		if err != nil {
			return nil, sdk.ErrUnknownAddress(fmt.Sprintf("can't get address from bench32: %v", err))
		}
		key := createKeyForAddr(round, addr)
		if !dsStore.Has(key) {
			return nil, sdk.ErrUnknownRequest("addresses list and real decryption share sender doesn't meet")
		}
		dsBytes := dsStore.Get(key)
		var dsJSON types.DecryptionShareJSON
		err = k.cdc.UnmarshalJSON(dsBytes, &dsJSON)
		if err != nil {
			return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarthsal decryption share: %v", err))
		}
		ds, err2 := dsJSON.Deserialize()
		if err2 != nil {
			return nil, err2
		}
		dsList = append(dsList, ds)
	}
	return dsList, nil
}

// GetRandom returns random bytes array of the given round
func (k *Keeper) GetRandom(ctx sdk.Context, round uint64) ([]byte, sdk.Error) {
	stage := k.GetStage(ctx, round)
	if stage != stageCompleted {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("wrong round stage: %v. round: %v", stage, round))
	}
	store := ctx.KVStore(k.storeRandomResultsKey)
	keyBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(keyBytes, round)
	if !store.Has(keyBytes) {
		return nil, sdk.ErrInternal("There is not round result in the store")
	}
	result := store.Get(keyBytes)
	return result, nil
}

// GetStage returns stage of the given round
func (k *Keeper) GetStage(ctx sdk.Context, round uint64) string {
	store := ctx.KVStore(k.storeKey)
	keyBytes := createKeyBytesByRound(round, keyStage)
	if !store.Has(keyBytes) {
		return stageUnstarted
	}
	stage := string(store.Get(keyBytes))
	return stage
}

func (k *Keeper) setStage(ctx sdk.Context, round uint64, stage string) {
	store := ctx.KVStore(k.storeKey)
	keyBytes := createKeyBytesByRound(round, keyStage)
	store.Set(keyBytes, []byte(stage))
}

// computeAggregatedCiphertext computes and STORES aggregated ciphertext
func (k *Keeper) computeAggregatedCiphertext(ctx sdk.Context, round uint64) sdk.Error {
	store := ctx.KVStore(k.storeKey)
	keyBytes := createKeyBytesByRound(round, keyAggregatedCiphertext)
	allCts, err := k.GetAllCiphertexts(ctx, round)
	if err != nil {
		return err
	}
	ctArray := make([]elgamal.Ciphertext, 0, len(allCts))
	for _, ct := range allCts {
		ctArray = append(ctArray, ct.Ciphertext)
	}
	aggregatedCiphertext := elgamal.AggregateCiphertext(k.group, ctArray)
	aCSer, err1 := elgamal.NewCiphertextJSON(&aggregatedCiphertext, P256)
	if err1 != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't serialize aggregated ciphertext: %v", err1))
	}
	aCSerBytes, err2 := k.cdc.MarshalJSON(aCSer)
	if err2 != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't marshal aggregated ciphertext: %v", err2))
	}
	store.Set(keyBytes, aCSerBytes)

	return nil
}

func (k *Keeper) computeRandomResult(ctx sdk.Context, round uint64) sdk.Error {
	store := ctx.KVStore(k.storeRandomResultsKey)
	keyBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(keyBytes, round)
	dsList, err := k.GetAllDecryptionShares(ctx, round)
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't get all decryption shares from store: %v", err))
	}
	ds := make([]*share.PubShare, 0, len(dsList))
	for _, decShare := range dsList {
		ds = append(ds, &decShare.DecShare)
	}
	aggCt, err := k.GetAggregatedCiphertext(ctx, round)
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't get aggregated ciphertext from store: %v", err))
	}

	n, err := k.GetKeyHoldersNumber(ctx)
	if err != nil {
		return err
	}

	resultPoint := elgamal.Decrypt(P256, *aggCt, ds, int(n))
	hash := P256.Hash()
	_, err2 := resultPoint.MarshalTo(hash)
	if err2 != nil {
		return sdk.ErrInternal(fmt.Sprintf("failed to marshal result point to hash: %v", err))
	}
	result := hash.Sum(nil)
	if round == 0 {
		t := time.Now().UTC()
		k.resTime = t
	} else {
		t1 := time.Now().UTC()
		secRound := t1.Sub(k.resTime)
		k.randmetric.Random.Set(secRound.Seconds())
		k.resTime = t1
	}
	k.randmetric.CountRandom.Inc()
	store.Set(keyBytes, result)
	return nil
}

// for tests purposes
func (k *Keeper) forceRoundStage(ctx sdk.Context, round uint64, stage string) {
	store := ctx.KVStore(k.storeKey)
	keyBytes := createKeyBytesByRound(round, keyStage)
	store.Set(keyBytes, []byte(stage))
}

// for tests purposes
func (k *Keeper) forceCurrentRound(ctx sdk.Context, round uint64) {
	store := ctx.KVStore(k.storeKey)
	roundBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(roundBytes, round)
	store.Set([]byte(keyCurrentRound), roundBytes)
}
