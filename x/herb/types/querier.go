package types

import (
	"fmt"
	"strconv"

	"github.com/dgamingfoundation/HERB/x/herb/elgamal"
)

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

type QueryCurrentRoundRes struct {
	Round uint64 `json:"round"`
}

func (r QueryCurrentRoundRes) String() string {
	return strconv.FormatUint(r.Round, 10)
}

type QueryStageRes struct {
	Stage string `json:"stage"`
}

func (r QueryStageRes) String() string {
	return r.Stage
}

type QueryResultRes struct {
	Random []byte `json:"random_value"`
}

func (r QueryResultRes) String() string {
	return fmt.Sprintf("%v", r.Random)
}

type QueryAggregatedCtRes struct {
	CiphertextJSON elgamal.CiphertextJSON `json:"ciphertext"`
}

func (r QueryAggregatedCtRes) String() string {
	return r.CiphertextJSON.String()
}

type QueryAllCtRes struct {
	CiphertextShares []*CiphertextShareJSON `json:"ciphertext_shares"`
}

func (r QueryAllCtRes) String() string {
	str := ""
	for _, ctShare := range r.CiphertextShares {
		str = str + fmt.Sprintf("Entropy provider address: %v \n Ciphertext: %v \n", ctShare.EntropyProvider.String(), ctShare.Ciphertext.String())
	}
	str = str + fmt.Sprintf("Total ct-shares: %v\n", len(r.CiphertextShares))
	return str
}

type QueryAllDescryptionSharesRes struct {
	DecryptionShares []DecryptionShareJSON `json:"decryption_shares"`
}

func (r QueryAllDescryptionSharesRes) String() string {
	str := ""
	for _, share := range r.DecryptionShares {
		str = str + fmt.Sprintf("Key holder address: %v \n Descryption Share: %v \n", share.KeyHolderAddr.String(), share.DecShare)
	}
	str = str + fmt.Sprintf("Total shares: %v\n", len(r.DecryptionShares))
	return str
}
