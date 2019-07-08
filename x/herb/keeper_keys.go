package herb

import (
	"strconv"
)


const (
	// key prefixes for defining item in the store by round
	keyCiphertextParts      = "keyCt"     //ciphtetextParts for the round
	keyDecryptionShares     = "keyDS"     //descryption shares
	keyAggregatedCiphertext = "keyACt"    // aggregated ciphertext
	keyRandomResult         = "keyResult" // random point as result of the round
	keyStage                = "keyStage"
	keyCommonKey            = "keyCommon"      //public key
	keyVerificationKeys     = "keyVK"          //verification keys with id
	keyCurrentRound         = "keyCurentRound" //current generation round
	keyKeyHoldersNumber 	= "keyKeyHoldersNumber" //number of key holders

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
