package herb

import (
	"strconv"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	// key prefixes for defining item in the store by round
	keyAggregatedCiphertext = "keyAggregatedCiphertext" // aggregated ciphertext
	keyRandomResult         = "keyRandomResult"         // result
	keyStage                = "keyStage"
	keyCommonKey            = "keyCommonKey"        //public key
	keyVerificationKeys     = "keyVerificationKeys" //verification keys with id
	keyCurrentRound         = "keyCurentRound"      //current generation round
	keyKeyHoldersNumber     = "keyKeyHoldersNumber" //number of key holders
	keyThresholdCiphertexts = "keyThresholdCiphertexts"
	keyThresholdDecrypt     = "keyThresholdDecrypt"

	//round stages: ciphertext shares collecting, descryption shares collecting, fresh random number
	stageCtCollecting = "stageCtCollecting"
	stageDSCollecting = "stageDSCollecting"
	stageCompleted    = "stageCompleted"
	stageUnstarted    = "stageUnstarted"
)

func createKeyBytesByRound(round uint64, keyPrefix string) []byte {
	roundStr := strconv.FormatUint(round, 10)
	keyStr := roundStr + keyPrefix
	keyBytes := []byte(keyStr)
	return keyBytes
}

func createKeyBytesByAddr(round uint64, addr sdk.AccAddress) []byte {
	keyStr := strconv.FormatUint(round, 10) + addr.String()
	return []byte(keyStr)
}
