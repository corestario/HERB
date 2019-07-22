package herb

import (
	"strconv"
)


const (
	// key prefixes for defining item in the store by round
	keyAggregatedCiphertext = "keyAggregatedCiphertext"    // aggregated ciphertext
	keyStage                = "keyStage"
	keyCommonKey            = "keyCommonKey"      //public key
	keyVerificationKeys     = "keyVerificationKeys"          //verification keys with id
	keyCurrentRound         = "keyCurentRound" //current generation round
	keyKeyHoldersNumber 	= "keyKeyHoldersNumber" //number of key holders
	keyThresholdParts 		= "keyThresholdParts"
	keyThresholdDecrypt 	= "keyThresholdDecrypt"

	//round stages: ciphertext parts collecting, descryption shares collecting, fresh random number
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
