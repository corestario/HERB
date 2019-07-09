package types

const (
	QueryAggregatedCt = "queryAggregatedCiphertext"
	QueryAllCt        = "queryAllCiphertexts"
	QueryAllDescryptionShares = "queryAllDecryptionShares"
	QueryRandom = "queryRandom"
	QueryStage = "queryStage"
	QueryKeyHoldersNumber = "queryKeyHoldersNumber"
	QueryCurrentRound = "queryCurrentRound"
)

type QueryByRound struct {
	Round int64
}

// NewQueryByRound creates a new instance of QueryByRound
func NewQueryByRound(round int64) QueryByRound {
	return QueryByRound{
		Round: round,
	}
}
