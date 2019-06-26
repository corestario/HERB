package types

const (
	QueryAggregatedCt = "aggregatedCiphertext"
)

type QueryAggregatedCtParams struct {
	Round uint64
}

// NewQueryAggregatedCtParams creates a new instance of QueryAggregatedCtParams
func NewQueryAggregatedCtParams(round uint64) QueryAggregatedCtParams {
	return QueryAggregatedCtParams{
		Round: round,
	}
}



