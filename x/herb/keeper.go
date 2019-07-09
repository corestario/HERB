package herb

import (
	"encoding/binary"
	"fmt"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
	"github.com/dgamingfoundation/HERB/x/herb/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
)

// Keeper maintains the link to data storage and exposes methods for the HERB protocol actions
type Keeper struct {
	storeKey sdk.StoreKey
	group    kyber.Group

	cdc *codec.Codec
}

// NewKeeper creates new instances of the HERB Keeper
func NewKeeper(storeKey sdk.StoreKey, cdc *codec.Codec) Keeper {
	return Keeper{
		storeKey: storeKey,
		group:    P256,

		cdc: cdc,
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
	store := ctx.KVStore(k.storeKey)
	round := k.CurrentRound(ctx)
	stage := k.GetStage(ctx, round)
	pubKey, err2 := k.GetCommonPublicKey(ctx)
	if err != nil {
		return err2
	}
	err = elgamal.RKVerify(P256, ctPart.Ciphertext.PointB, k.group.Point().Base(), pubKey, ctPart.RKproof)
	if err != nil {
		return sdk.ErrUnknownRequest("RK proof isn't correct")
	}

	if k.CurrentRound(ctx) == 0 && stage == stageUnstarted {
		stage = stageCtCollecting
		k.setStage(ctx, round, stage)
	}

	if stage != stageCtCollecting {
		return sdk.ErrUnknownRequest(fmt.Sprintf("round is not on the ciphertext collecting stage. Current stage: %v", stage))
	}

	keyBytesCt := createKeyBytesByRound(round, keyCiphertextParts)
	ctMap := make(map[string]*types.CiphertextPart)
	if store.Has(keyBytesCt) {
		ctMapBytes := store.Get(keyBytesCt)
		var ctMapJSON map[string]*types.CiphertextPartJSON
		err = k.cdc.UnmarshalJSON(ctMapBytes, &ctMapJSON)
		if err != nil {
			return sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarshal map from the store: %v", err))
		}
		ctMap, err2 = types.CiphertextMapDeserialize(ctMapJSON)
		if err2 != nil {
			return err2
		}
	}
	if _, ok := ctMap[ctPart.EntropyProvider.String()]; ok {
		return sdk.ErrInvalidAddress("entropy provider has already send ciphertext part")
	}

	ctMap[ctPart.EntropyProvider.String()] = ctPart
	newCtMapJSON, err4 := types.CiphertextMapSerialize(ctMap)
	if err4 != nil {
		return err4
	}
	newCtMapBytes, err := k.cdc.MarshalJSON(newCtMapJSON)
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't marshal map for the store: %v", err2))
	}
	store.Set(keyBytesCt, newCtMapBytes)

	t, err2 := k.GetThresholdParts(ctx)
	if err2 != nil {
		return err2
	}

	if uint64(len(ctMap)) >= t {
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
	store := ctx.KVStore(k.storeKey)
	round := k.CurrentRound(ctx)
	stage := k.GetStage(ctx, round)
	if stage != stageDSCollecting {
		return sdk.ErrUnknownRequest(fmt.Sprintf("wrong round stage: %v. round: %v", stage, round))
	}
	ACiphertext, err := k.GetAggregatedCiphertext(ctx, round)
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't get aggregated ciphertext: %v", err))
	}
	keyVKBytes := []byte(keyVerificationKeys)
	if !store.Has(keyVKBytes) {
		return sdk.ErrUnknownRequest("Verification keys map isn't exist")
	}
	VKBytes := store.Get(keyVKBytes)
	VKStr := make(map[string]*types.VerificationKeyJSON)
	err2 := k.cdc.UnmarshalJSON(VKBytes, &VKStr)
	if err2 != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarshal map from the store: %v", err2))
	}
	vkMap, err := types.VerificationKeyMapDeserialize(VKStr)
	if err != nil {
		return err
	}
	err2 = elgamal.DLEVerify(P256, ds.DLEproof, k.group.Point().Base(), ACiphertext.PointA, vkMap[ds.KeyHolder.String()].VK, ds.DecShare.V)
	if err2 != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("DLE proof isn't correct: %v", err2))
	}
	keyBytes := createKeyBytesByRound(round, keyDecryptionShares)
	dsMap := make(map[string]*types.DecryptionShare)
	if store.Has(keyBytes) {
		dsMapBytes := store.Get(keyBytes)
		var dsMapJSON map[string]*types.DecryptionShareJSON
		err2 = k.cdc.UnmarshalJSON(dsMapBytes, &dsMapJSON)
		if err2 != nil {
			return sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarshal map from the store: %v", err2))
		}
		dsMap, err = types.DecryptionSharesMapDeserialize(dsMapJSON)
		if err != nil {
			return err
		}
	}

	if _, ok := dsMap[ds.KeyHolder.String()]; ok {
		return sdk.ErrInvalidAddress("key holder has already send a decryption share")
	}

	dsMap[ds.KeyHolder.String()] = ds
	newDsMapJSON, err := types.DecryptionSharesMapSerialize(dsMap)
	if err != nil {
		return err
	}
	newDsMapBytes, err2 := k.cdc.MarshalJSON(newDsMapJSON)
	if err2 != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't marshal map for the store: %v", err2))
	}
	store.Set(keyBytes, newDsMapBytes)

	t, err := k.GetThresholdDecryption(ctx)
	if err != nil {
		return err
	}


	if uint64(len(dsMap)) >= t {
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
func (k *Keeper) GetAllCiphertexts(ctx sdk.Context, round uint64) (map[string]*types.CiphertextPart, sdk.Error) {
	store := ctx.KVStore(k.storeKey)
	stage := k.GetStage(ctx, round)

	if stage == stageUnstarted {
		return nil, sdk.ErrUnknownRequest("round hasn't started yet")
	}

	keyBytes := createKeyBytesByRound(round, keyCiphertextParts)

	//if store doesn't have such key -> no cts was added
	if !store.Has(keyBytes) {
		return map[string]*types.CiphertextPart{}, nil
	}
	ctMapBytes := store.Get(keyBytes)
	var ctMapJSON map[string]*types.CiphertextPartJSON
	err1 := k.cdc.UnmarshalJSON(ctMapBytes, &ctMapJSON)
	if err1 != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarshal map from store: %v", err1))
	}
	ctMap, err := types.CiphertextMapDeserialize(ctMapJSON)
	if err != nil {
		return nil, err
	}
	return ctMap, nil
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
	var newaCSer *elgamal.CiphertextJSON
	err := k.cdc.UnmarshalJSON(result, &newaCSer)
	if err != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarshal aggregated ciphertext: %v", err))
	}
	newCt, err := newaCSer.Deserialize()
	if err != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't deserialize aggregated ciphertext: %v", err))
	}
	return newCt, nil
}

// GetAllDecryptionShares returns all decryption shares for the given round
func (k *Keeper) GetAllDecryptionShares(ctx sdk.Context, round uint64) (map[string]*types.DecryptionShare, sdk.Error) {
	stage := k.GetStage(ctx, round)
	if stage != stageDSCollecting && stage != stageCompleted {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("wrong round stage: %v. round: %v", stage, round))
	}

	store := ctx.KVStore(k.storeKey)
	keyBytes := createKeyBytesByRound(round, keyDecryptionShares)
	if !store.Has(keyBytes) {
		return map[string]*types.DecryptionShare{}, nil
	}
	dsMapBytes := store.Get(keyBytes)
	var dsMapJSON map[string]*types.DecryptionShareJSON
	err1 := k.cdc.UnmarshalJSON(dsMapBytes, &dsMapJSON)
	if err1 != nil {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarshal map from store: %v", err1))
	}
	dsMap, err := types.DecryptionSharesMapDeserialize(dsMapJSON)
	if err != nil {
		return nil, err
	}
	return dsMap, nil
}

// GetRandom returns random bytes array of the given round
func (k *Keeper) GetRandom(ctx sdk.Context, round uint64) ([]byte, sdk.Error) {
	stage := k.GetStage(ctx, round)
	if stage != stageCompleted {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("wrong round stage: %v. round: %v", stage, round))
	}

	store := ctx.KVStore(k.storeKey)
	keyBytes := createKeyBytesByRound(round, keyRandomResult)
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
	aCSer, err1 := elgamal.NewCiphertextJSON(&aggregatedCiphertext)
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
	store := ctx.KVStore(k.storeKey)
	keyBytes := createKeyBytesByRound(round, keyRandomResult)
	dsMap, err := k.GetAllDecryptionShares(ctx, round)
	if err != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't get all decryption shares from store: %v", err))
	}
	ds := make([]*share.PubShare, 0, len(dsMap))
	for _, decShare := range dsMap {
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
