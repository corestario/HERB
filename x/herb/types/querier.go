package types

const (
	QueryAggregatedCt = "aggregatedCiphertext"
	QueryAllCt        = "AllCiphertexts"
)

type QueryCtParams struct {
	Round uint64
}

// NewQueryCtParams creates a new instance of QueryCtParams
func NewQueryCtParams(round uint64) QueryCtParams {
	return QueryCtParams{
		Round: round,
	}
}
