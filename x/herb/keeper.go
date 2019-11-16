package herb

import (
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"github.com/corestario/HERB/x/herb/elgamal"
	"github.com/corestario/HERB/x/herb/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
)

// Keeper maintains the link to data storage and exposes methods for the HERB protocol actions
type Keeper struct {
	storeKey                 sdk.StoreKey
	group                    kyber.Group
	storeCiphertextSharesKey *sdk.KVStoreKey
	storeDecryptionSharesKey *sdk.KVStoreKey
	cdc                      *codec.Codec
	randmetric               *Metrics
	resTime                  time.Time
	verificationKeys         map[string]types.VerificationKey
}

// NewKeeper creates new instances of the HERB Keeper
func NewKeeper(storeKey sdk.StoreKey, storeCiphertextShares *sdk.KVStoreKey, storeDecryptionShares *sdk.KVStoreKey, cdc *codec.Codec) Keeper {
	randmetric := PrometheusMetrics()
	t := time.Now().UTC()
	return Keeper{
		storeKey:                 storeKey,
		group:                    P256,
		storeCiphertextSharesKey: storeCiphertextShares,
		storeDecryptionSharesKey: storeDecryptionShares,
		cdc:                      cdc,
		randmetric:               randmetric,
		resTime:                  t,
	}
}

// SetCiphertext store the ciphertext from the entropyProvider to the kv-store
func (k *Keeper) SetCiphertext(ctx sdk.Context, ctShare *types.CiphertextShare) sdk.Error {
	defer func() {
		if r := recover(); r != nil {
			log.Println("PANIC:", r)
		}
	}()
	if ctShare.EntropyProvider.Empty() {
		return sdk.ErrInvalidAddress("entropy provider can't be empty!")
	}
	round := k.CurrentRound(ctx)
	stage := k.GetStage(ctx, round)
	pubKey, err1 := k.GetCommonPublicKey(ctx)
	if err1 != nil {
		return err1
	}
	err := elgamal.CEVerify(P256, k.group.Point().Base(), pubKey, ctShare.Ciphertext.PointA, ctShare.Ciphertext.PointB, ctShare.CEproof)
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("CE proof isn't correct: %v", err))
	}

	if k.CurrentRound(ctx) == 0 && stage == stageUnstarted {
		err1 = k.InitializeVerificationKeys(ctx)
		if err1 != nil {
			return err1
		}
		stage = stageCtCollecting
		k.setStage(ctx, round, stage)
	}

	if stage != stageCtCollecting {
		return sdk.ErrUnknownRequest(fmt.Sprintf("round is not on the ciphertext collecting stage. Current stage: %v", stage))
	}
	ctStore := ctx.KVStore(k.storeCiphertextSharesKey)
	keyBytesAllCt := []byte(fmt.Sprintf("rd_%d", round))
	t, err1 := k.GetThresholdCiphertexts(ctx)
	if err1 != nil {
		return err1
	}

	var addrList []string
	if ctStore.Has(keyBytesAllCt) {
		addrListBytes := ctStore.Get(keyBytesAllCt)
		err := k.cdc.UnmarshalJSON(addrListBytes, &addrList)
		if err != nil {
			return sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarshal list of all addresses from the store: %v", err))
		}
	}
	addrList = append(addrList, ctShare.EntropyProvider.String())
	newAddrListBytes, err := k.cdc.MarshalJSON(addrList)
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't marshal list of all addresses: %v", err))
	}

	keyBytesCt := createKeyBytesByAddr(round, ctShare.EntropyProvider)
	if ctStore.Has(keyBytesCt) {
		return sdk.ErrInvalidAddress("entropy provider has already sentf ciphertext share")
	}
	ctJSON, err := types.NewCiphertextShareJSON(ctShare)
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't serialize ctShare: %v", err))
	}
	ctBytes, err := k.cdc.MarshalJSON(ctJSON)
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't marshall ctShare: %v", err))
	}
	aggregatedCt, err1 := k.GetAggregatedCiphertext(ctx, round)
	if err1 != nil {
		return err1
	}
	var newAggregatedCt elgamal.Ciphertext
	if aggregatedCt == nil {
		newAggregatedCt = ctShare.Ciphertext
	} else {
		newAggregatedCt = elgamal.AggregateCiphertext(P256, []elgamal.Ciphertext{ctShare.Ciphertext, *aggregatedCt})
	}
	err1 = k.SetAggregatedCiphertext(ctx, round, &newAggregatedCt)
	if err1 != nil {
		return err1
	}
	ctStore.Set(keyBytesCt, ctBytes)
	ctStore.Set(keyBytesAllCt, newAddrListBytes)

	if uint64(len(addrList)) >= t {
		k.setStage(ctx, round, stageDSCollecting)
	}
	return nil
}

func (k *Keeper) SetAggregatedCiphertext(ctx sdk.Context, round uint64, ct *elgamal.Ciphertext) sdk.Error {
	defer func() {
		if r := recover(); r != nil {
			log.Println("PANIC:", r)
		}
	}()
	store := ctx.KVStore(k.storeKey)
	keyBytes := createKeyBytesByRound(round, keyAggregatedCiphertext)

	ctJSON, err := elgamal.NewCiphertextJSON(ct, P256)
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't serialize aggregated ct: %v", err))
	}
	ctBytes, err := k.cdc.MarshalJSON(ctJSON)
	if err != nil {
		return sdk.ErrInternal(fmt.Sprintf("can't marhsal aggregated ct: %v", err))
	}
	store.Set(keyBytes, ctBytes)
	return nil
}

// SetDecryptionShare stores decryption share for the current round
func (k *Keeper) SetDecryptionShare(ctx sdk.Context, ds *types.DecryptionShare) sdk.Error {
	defer func() {
		if r := recover(); r != nil {
			log.Println("PANIC:", r)
		}
	}()
	if ds.KeyHolderAddr.Empty() {
		return sdk.ErrInvalidAddress("key Holder can't be empty!")
	}

	round := k.CurrentRound(ctx)
	stage := k.GetStage(ctx, round)
	if stage != stageDSCollecting {
		return sdk.ErrUnknownRequest(fmt.Sprintf("wrong round stage: %v. round: %v", stage, round))
	}
	aggCiphertext, err1 := k.GetAggregatedCiphertext(ctx, round)
	if err1 != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't get aggregated ciphertext: %v", err1))
	}

	vkOwner, ok := k.verificationKeys[ds.KeyHolderAddr.String()]
	if !ok {
		return sdk.ErrUnknownRequest("verification key isn't exist")
	}

	err := elgamal.DLEQVerify(P256, ds.DLEQproof, k.group.Point().Base(), aggCiphertext.PointA, vkOwner.Key, ds.DecShare.V)
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("DLEQ proof isn't correct: %v", err))
	}

	dsStore := ctx.KVStore(k.storeDecryptionSharesKey)
	keyBytes := createKeyBytesByAddr(round, vkOwner.Sender)
	keyAllShares := []byte(fmt.Sprintf("rd_%d", round))

	var addrList []string
	if dsStore.Has(keyAllShares) {
		addrListBytes := dsStore.Get(keyAllShares)
		err = k.cdc.UnmarshalJSON(addrListBytes, &addrList)
		if err != nil {
			return sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarshal list of all addresses from the store: %v", err))
		}
	}
	addrList = append(addrList, ds.KeyHolderAddr.String())
	newAddrListBytes, err := k.cdc.MarshalJSON(addrList)
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't marshal list of all addresses: %v", err))
	}

	if dsStore.Has(keyBytes) {
		return sdk.ErrInvalidAddress("key holder has already send decryption share")
	}
	dsJSON, err1 := types.NewDecryptionShareJSON(ds)
	if err1 != nil {
		return err1
	}
	dsBytes, err := k.cdc.MarshalJSON(dsJSON)
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't marshall decryption share: %v", err))
	}

	dsStore.Set(keyBytes, dsBytes)
	dsStore.Set(keyAllShares, newAddrListBytes)

	t, err1 := k.GetThresholdDecryption(ctx)
	if err1 != nil {
		return err1
	}

	if uint64(len(addrList)) >= t {
		err := k.SetRandomResult(ctx, round)
		if err != nil {
			return err
		}
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

// GetAllCiphertexts returns all ciphertext shares for the given round as go-slice
func (k *Keeper) GetAllCiphertexts(ctx sdk.Context, round uint64) ([]*types.CiphertextShare, sdk.Error) {
	ctStore := ctx.KVStore(k.storeCiphertextSharesKey)
	stage := k.GetStage(ctx, round)

	if stage == stageUnstarted {
		return nil, sdk.ErrUnknownRequest("round hasn't started yet")
	}

	keyBytesAllCt := []byte(fmt.Sprintf("rd_%d", round))

	//if store doesn't have such key -> no cts was added
	if !ctStore.Has(keyBytesAllCt) {
		return []*types.CiphertextShare{}, nil
	}

	addrListBytes := ctStore.Get(keyBytesAllCt)
	var addrList []string
	err := k.cdc.UnmarshalJSON(addrListBytes, &addrList)
	if err != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarshal list of all adderesses from store: %v", err))
	}
	ctList := make([]*types.CiphertextShare, 0, len(addrList))
	for _, addrStr := range addrList {
		addr, err := sdk.AccAddressFromBech32(addrStr)
		if err != nil {
			return nil, sdk.ErrUnknownAddress(fmt.Sprintf("can't get address from bench32: %v", err))
		}
		key := createKeyBytesByAddr(round, addr)
		if !ctStore.Has(key) {
			return nil, sdk.ErrUnknownRequest("addresses list and real ciphertext providers doesn't meet")
		}
		ctBytes := ctStore.Get(key)
		var ctJSON types.CiphertextShareJSON
		err = k.cdc.UnmarshalJSON(ctBytes, &ctJSON)
		if err != nil {
			return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarthsal ciphertext: %v", err))
		}
		ct, err1 := ctJSON.Deserialize()
		if err1 != nil {
			return nil, err1
		}
		ctList = append(ctList, ct)
	}
	return ctList, nil
}

// GetAggregatedCiphertext aggregate all sended ciphertext shares in one ciphertext and returns it
func (k *Keeper) GetAggregatedCiphertext(ctx sdk.Context, round uint64) (*elgamal.Ciphertext, sdk.Error) {
	store := ctx.KVStore(k.storeKey)
	keyBytes := createKeyBytesByRound(round, keyAggregatedCiphertext)
	if !store.Has(keyBytes) {
		return nil, nil
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

	keyAllShares := []byte(fmt.Sprintf("rd_%d", round))

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
		key := createKeyBytesByAddr(round, addr)
		if !dsStore.Has(key) {
			return nil, sdk.ErrUnknownRequest("addresses list and real decryption share sender doesn't meet")
		}
		dsBytes := dsStore.Get(key)
		var dsJSON types.DecryptionShareJSON
		err = k.cdc.UnmarshalJSON(dsBytes, &dsJSON)
		if err != nil {
			return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarthsal decryption share: %v", err))
		}
		ds, err1 := dsJSON.Deserialize()
		if err1 != nil {
			return nil, err1
		}
		dsList = append(dsList, ds)
	}
	return dsList, nil
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
func (k *Keeper) setRound(ctx sdk.Context, round uint64) {
	currentRound := round
	store := ctx.KVStore(k.storeKey)
	roundBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(roundBytes, currentRound)
	store.Set([]byte(keyCurrentRound), roundBytes)
}

func (k *Keeper) SetRandomResult(ctx sdk.Context, round uint64) sdk.Error {
	defer func() {
		if r := recover(); r != nil {
			log.Println("PANIC:", r)
		}
	}()
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
	store := ctx.KVStore(k.storeKey)
	keyBytes := createKeyBytesByRound(round, keyRandomResult)
	store.Set(keyBytes, result)
	return nil
}
func (k *Keeper) RandomResult(ctx sdk.Context, round uint64) ([]byte, sdk.Error) {
	store := ctx.KVStore(k.storeKey)
	keyBytes := createKeyBytesByRound(round, keyRandomResult)
	if !store.Has(keyBytes) {
		return nil, sdk.ErrUnknownRequest("can't get random result from store: %v")
	}
	result := store.Get(keyBytes)
	return result, nil
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
