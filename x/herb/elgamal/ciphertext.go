package elgamal

import (
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	kyberenc "go.dedis.ch/kyber/v3/util/encoding"
)

//Ciphertext is usual ElGamal ciphertext C = (a, b)
//Here a, b - the elliptic curve's points
type Ciphertext struct {
	PointA kyber.Point `json:"point_a"`
	PointB kyber.Point `json:"point_b"`
}

//IdentityCiphertext creates ciphertext which is neutral with respect to plaintext group operation (after ciphertext aggregation operation)
func IdentityCiphertext(group kyber.Group) Ciphertext {
	return Ciphertext{group.Point().Null(), group.Point().Null()}
}

//Decrypt takes decrypt shares (shares) from all participants and decrypt the ciphertext C
func Decrypt(group kyber.Group, C Ciphertext, parts []*share.PubShare, n int) kyber.Point {
	D, _ := share.RecoverCommit(group, parts, len(parts), n)
	M := group.Point().Sub(C.PointB, D)
	return M
}

//Equal compares two ciphertexts and returns true if ct = ct1
func (ct Ciphertext) Equal(ct1 Ciphertext) bool {
	return ct.PointA.Equal(ct1.PointA) && ct.PointB.Equal(ct1.PointB)
}

//String
func (ct Ciphertext) String() string {
	str := fmt.Sprintf("A: %v, B: %v", ct.PointA.String(), ct.PointB.String())
	return str
}

//AggregateCiphertext takes the set of ciphertextes shares:
//parts[0] = (A0, B0), ..., parts[n] = (An, Bn)
//and returns aggregated ciphertext C = (A1 + A2 + ... + An, B1 + B2 + ... + Bn)
func AggregateCiphertext(group kyber.Group, parts []Ciphertext) Ciphertext {
	if len(parts) == 0 {
		return IdentityCiphertext(group)
	}
	ct := Ciphertext{parts[0].PointA, parts[0].PointB}
	for i := 1; i < len(parts); i++ {
		ct.PointA = group.Point().Add(ct.PointA, parts[i].PointA)
		ct.PointB = group.Point().Add(ct.PointB, parts[i].PointB)
	}

	return ct
}

type CiphertextJSON struct {
	PointA string `json:"point_a"`
	PointB string `json:"point_b"`
}

func (ct CiphertextJSON) String() string {
	return fmt.Sprintf("(%s, %s)", ct.PointA, ct.PointB)
}

func NewCiphertextJSON(ciphertext *Ciphertext, group kyber.Group) (*CiphertextJSON, error) {
	aJSON, err := kyberenc.PointToStringHex(group, ciphertext.PointA)
	if err != nil {
		return nil, fmt.Errorf("failed to encode Point A: %v", err)
	}
	bJSON, err := kyberenc.PointToStringHex(group, ciphertext.PointB)
	if err != nil {
		return nil, fmt.Errorf("failed to encode Point B: %v", err)
	}
	return &CiphertextJSON{
		PointA: aJSON,
		PointB: bJSON,
	}, nil
}

func (ctJSON *CiphertextJSON) Deserialize(group kyber.Group) (*Ciphertext, error) {
	pointA, err := kyberenc.StringHexToPoint(group, ctJSON.PointA)
	if err != nil {
		return nil, fmt.Errorf("failed to decode point A : %v", err)
	}
	pointB, err := kyberenc.StringHexToPoint(group, ctJSON.PointB)
	if err != nil {
		return nil, fmt.Errorf("failed to decode point A : %v", err)
	}
	return &Ciphertext{
		PointA: pointA,
		PointB: pointB,
	}, nil
}
