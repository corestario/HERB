package types

const (
	QueryAggregatedCt         = "queryAggregatedCiphertext"
	QueryAllCt                = "queryAllCiphertexts"
	QueryAllDescryptionShares = "queryAllDecryptionShares"
	QueryStage                = "queryStage"
	QueryCurrentRound         = "queryCurrentRound"
	QueryResult               = "queryResult"
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
