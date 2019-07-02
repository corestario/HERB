package types

const (
	QueryAggregatedCt = "aggregatedCiphertext"
	QueryAllCt        = "allCiphertexts"
	QueryAllDescryptionShares = "allDecryptionShares"
)

type QueryByRound struct {
	Round uint64
}

// NewQueryByRound creates a new instance of QueryByRound
func NewQueryByRound(round uint64) QueryByRound {
	return QueryByRound{
		Round: round,
	}
}
