package elgamal

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/nist"
	"go.dedis.ch/kyber/v3/share"
)

//Ciphertext is usual ElGamal ciphertext C = (a, b)
//Here a, b - the elliptic curve's points
type Ciphertext struct {
	PointA kyber.Point `json:"pointA"`
	PointB kyber.Point `json:"pointB"`
}

//IdentityCiphertext creates ciphertext which is neutral with respect to plaintext group operation (after ciphertext aggregation operation)
func IdentityCiphertext(group kyber.Group) Ciphertext {
	return Ciphertext{group.Point().Null(), group.Point().Null()}
}

//Decrypt takes decrypt parts (shares) from all participants and decrypt the ciphertext C
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

//AggregateCiphertext takes the set of ciphertextes parts:
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
	PointA string `json:"pointA"`
	PointB string `json:"pointB"`
}

func NewCiphertextJSON(ciphertext *Ciphertext) (*CiphertextJSON, error) {
	aBuf := bytes.NewBuffer(nil)
	aEnc := gob.NewEncoder(aBuf)
	if err := aEnc.Encode(ciphertext.PointA); err != nil {
		return nil, fmt.Errorf("failed to encode Point A: %v", err)
	}

	bBuf := bytes.NewBuffer(nil)
	bEnc := gob.NewEncoder(bBuf)
	if err := bEnc.Encode(ciphertext.PointB); err != nil {
		return nil, fmt.Errorf("failed to encode Point B: %v", err)
	}
	return &CiphertextJSON{
		PointA: base64.StdEncoding.EncodeToString(aBuf.Bytes()),
		PointB: base64.StdEncoding.EncodeToString(bBuf.Bytes()),
	}, nil
}

func (ctJSON *CiphertextJSON) Deserialize() (*Ciphertext, error) {
	ABytes, err := base64.StdEncoding.DecodeString(ctJSON.PointA)
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode point A: %v", err)
	}
	ADec := gob.NewDecoder(bytes.NewBuffer(ABytes))
	pointA := nist.NewBlakeSHA256P256().Point().Base()
	if err := ADec.Decode(&pointA); err != nil {
		return nil, fmt.Errorf("failed to decode point A : %v", err)
	}
	BBytes, err := base64.StdEncoding.DecodeString(ctJSON.PointB)
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode point B: %v", err)
	}
	BDec := gob.NewDecoder(bytes.NewBuffer(BBytes))
	pointB := nist.NewBlakeSHA256P256().Point().Base()
	if err := BDec.Decode(&pointB); err != nil {
		return nil, fmt.Errorf("failed to decode point B : %v", err)
	}
	return &Ciphertext{
		PointA: pointA,
		PointB: pointB,
	}, nil
}
