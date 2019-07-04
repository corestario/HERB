package herb

import (
	"fmt"
	"strconv"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
	"github.com/dgamingfoundation/HERB/x/herb/types"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	// key prefixes for defining item in the store by round
	keyCiphertextParts      = "keyCt"     //ciphtetextParts for the round
	keyDecryptionShares     = "keyDS"     //descryption shares
	keyAggregatedCiphertext = "keyACt"    // aggregated ciphertext
	keyRandomResult         = "keyResult" // random point as result of the round
	keyStage                = "keyStage"

	//round stages: ciphertext parts collecting, descryption shares collecting, fresh random number
	stageCtCollecting        = "stageCtCollecting"
	stageDSCollecting        = "stageDSCollecting"
	stageCompleted = "stageCompleted"
	stageUnstarted = "stageUnstarted"
)

// Keeper maintains the link to data storage and exposes methods for the HERB protocol actions
type Keeper struct {
	storeKey sdk.StoreKey
	group    kyber.Group

	currentRound        uint64
	thresholdDecryption uint64
	thresholdParts      uint64
	n                   uint64

	keyHoldersID		map[string]int

	cdc                 *codec.Codec
}

// NewKeeper creates new instances of the HERB Keeper
func NewKeeper(storeKey sdk.StoreKey, cdc *codec.Codec, thresholdDecryption uint64, thresholdParts uint64, n uint64) Keeper {
	return Keeper{
		storeKey:            storeKey,
		group:               P256,
		currentRound:        0,
		thresholdDecryption: thresholdDecryption,
		thresholdParts:      thresholdParts,
		n:                   n,

		keyHoldersID:		 map[string]int{},

		cdc:                 cdc,
	}
}

// SetCiphertext store the ciphertext from the entropyProvider to the kv-store
func (k *Keeper) SetCiphertext(ctx sdk.Context, ctPart *types.CiphertextPart) sdk.Error {
	if ctPart.EntropyProvider.Empty() {
		return sdk.ErrInvalidAddress("Entropy provider can't be empty!")
	}

	store := ctx.KVStore(k.storeKey)

	round := k.currentRound
	stage := k.getStage(ctx, round)
	if k.currentRound == 0 && stage == stageUnstarted{
		stage = stageCtCollecting
		k.setStage(ctx, round, stage)
	}

	if stage != stageCtCollecting {
		return sdk.ErrUnknownRequest(fmt.Sprintf("round is not on the ciphertext collecting stage. Current stage: %v", stage))
	}

	keyBytes := createKeyBytes(round, keyCiphertextParts)
	ctMap := make(map[string]*types.CiphertextPart)
	var err sdk.Error
	if store.Has(keyBytes) {
		ctMapBytes := store.Get(keyBytes)
		var ctMapJSON map[string]*types.CiphertextPartJSON
		err1 := k.cdc.UnmarshalJSON(ctMapBytes, &ctMapJSON)
		if err1 != nil {
			return sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarshal map from the store: %v", err1))
		}
		ctMap, err = types.CiphertextMapDeserialize(ctMapJSON)
		if err != nil {
			return err
		}
	}
	if _, ok := ctMap[ctPart.EntropyProvider.String()]; ok {
		return sdk.ErrInvalidAddress("entropy provider has already send ciphertext part")
	}

	ctMap[ctPart.EntropyProvider.String()] = ctPart
	newCtMapJSON, err := types.CiphertextMapSerialize(ctMap)
	if err != nil {
		return err
	}
	newCtMapBytes, err2 := k.cdc.MarshalJSON(newCtMapJSON)
	if err2 != nil {
		return sdk.ErrUnknownRequest(fmt.Sprintf("can't marshal map for the store: %v", err2))
	}
	store.Set(keyBytes, newCtMapBytes)

	if uint64(len(ctMap)) >= k.thresholdParts {
		err = k.computeAggregatedCiphertext(ctx, round)
		if err != nil {
			return err
		}
		k.setStage(ctx, round, stageDSCollecting)
	}
	return nil
}

// SetKeyHoldersID registers key holders' IDs for threshold encryption scheme
func (k *Keeper) SetKeyHoldersID(ctx sdk.Context, keyHolderAddr sdk.Address, keyHolderID int) sdk.Error {
	if keyHolderAddr.Empty() {
		return sdk.ErrInvalidAddress("key holder address is empty")
	}

	if keyHolderID < 0 {
		return sdk.ErrUnknownRequest("key holder ID must be positive!")
	}

	k.keyHoldersID[keyHolderAddr.String()] = keyHolderID
	return nil
}

// SetDecryptionShare stores decryption share for the current round
func (k *Keeper) SetDecryptionShare(ctx sdk.Context, ds *types.DecryptionShare) sdk.Error {
	if ds.KeyHolder.Empty() {
		return sdk.ErrInvalidAddress("Key Holder can't be empty!")
	}

	store := ctx.KVStore(k.storeKey)

	round := k.currentRound
	stage := k.getStage(ctx, round)
	if stage != stageDSCollecting {
		return sdk.ErrUnknownRequest(fmt.Sprintf("round is not on the decryption shares collecting stage. Current stage: %v", stage))
	}

	keyBytes := createKeyBytes(round, keyDecryptionShares)
	dsMap := make(map[string]*types.DecryptionShare)
	var err sdk.Error
	if store.Has(keyBytes) {
		dsMapBytes := store.Get(keyBytes)
		var dsMapJSON map[string]*types.DecryptionShareJSON
		err1 := k.cdc.UnmarshalJSON(dsMapBytes, &dsMapJSON)
		if err1 != nil {
			return sdk.ErrUnknownRequest(fmt.Sprintf("can't unmarshal map from the store: %v", err1))
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

	if uint64(len(dsMap)) >= k.thresholdDecryption {
		err = k.computeRandomResult(ctx, round)
		if err != nil {
			return err
		}
		k.setStage(ctx, round, stageCompleted)
		k.currentRound = k.currentRound + 1
		k.setStage(ctx, k.currentRound, stageCtCollecting)
	}

	return nil
}


// GetAllCiphertexts returns all ciphertext parts for the given round as go-slice
func (k *Keeper) GetAllCiphertexts(ctx sdk.Context, round uint64) (map[string]*types.CiphertextPart, sdk.Error) {
	store := ctx.KVStore(k.storeKey)
	stage := k.getStage(ctx, round)

	if stage == stageUnstarted {
		return nil, sdk.ErrUnknownRequest("round hasn't started yet")
	}

	keyBytes := createKeyBytes(round, keyCiphertextParts)

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

	stage := k.getStage(ctx, round)
	if stage != stageDSCollecting && stage != stageCompleted {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("wrong round stage: %v", stage))
	}

	store := ctx.KVStore(k.storeKey)
	keyBytes := createKeyBytes(round, keyAggregatedCiphertext)
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
	stage := k.getStage(ctx, round)
	if stage != stageDSCollecting && stage != stageCompleted {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("wrong round stage: %v", stage))
	}

	store := ctx.KVStore(k.storeKey)
	keyBytes := createKeyBytes(round, keyDecryptionShares)
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
	stage := k.getStage(ctx, round)
	if stage != stageCompleted {
		return nil, sdk.ErrUnknownRequest(fmt.Sprintf("wrong round stage: %v", stage))
	}

	store := ctx.KVStore(k.storeKey)
	keyBytes := createKeyBytes(round, keyRandomResult)
	if !store.Has(keyBytes) {
		return nil, sdk.ErrInternal("There is not round result in the store")
	}
	result := store.Get(keyBytes)
	return result, nil
}

func (k *Keeper) setStage(ctx sdk.Context, round uint64, stage string) {
	store := ctx.KVStore(k.storeKey)
	keyBytes := createKeyBytes(round, keyStage)
	store.Set(keyBytes, []byte(stage))
}

func createKeyBytes(round uint64, keyPrefix string) []byte {
	roundStr := strconv.FormatUint(round, 10)
	keyStr := roundStr + keyPrefix
	keyBytes := []byte(keyStr)
	return keyBytes
}

func (k *Keeper) getStage(ctx sdk.Context, round uint64) string {
	store := ctx.KVStore(k.storeKey)
	keyBytes := createKeyBytes(round, keyStage)
	if !store.Has(keyBytes) {
		return  stageUnstarted
	}
	stage := string(store.Get(keyBytes))
	return stage
}

// computeAggregatedCiphertext computes and STORES aggregated ciphertext
func (k *Keeper) computeAggregatedCiphertext(ctx sdk.Context, round uint64) sdk.Error {
	store := ctx.KVStore(k.storeKey)
	keyBytes := createKeyBytes(round, keyAggregatedCiphertext)
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
	keyBytes := createKeyBytes(round, keyRandomResult)
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
	resultPoint := elgamal.Decrypt(P256, *aggCt, ds, int(k.n))
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
	keyBytes := createKeyBytes(round, keyStage)
	store.Set(keyBytes, []byte(stage))
}

// for tests purposes
func (k *Keeper) forceCurrentRound(ctx sdk.Context, round uint64) {
	k.currentRound = round
}