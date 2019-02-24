package main

import (
	"errors"
	"fmt"

	"github.com/kyber-fun/elgamal"
	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/group/nist"
	dkg "go.dedis.ch/kyber/share/dkg/rabin"
	"go.dedis.ch/kyber/suites"
	"go.dedis.ch/kyber/util/random"
)

func DKG(suite suites.Suite, n int, t int) ([]*dkg.DistKeyGenerator, error) {
	//Paricipants create master secret and public keys
	participantSK := make([]kyber.Scalar, n)
	participantPK := make([]kyber.Point, n)
	for i := 0; i < n; i++ {
		participantSK[i] = suite.Scalar().Pick(suite.RandomStream())
		participantPK[i] = suite.Point().Mul(participantSK[i], nil)
	}

	//Each party creates they own copy of DKG-object
	dkgs := make([]*dkg.DistKeyGenerator, n)
	for i := 0; i < n; i++ {
		dkgi, err := dkg.NewDistKeyGenerator(suite, participantSK[i], participantPK, t)
		if err != nil {
			return nil, err
		}
		dkgs[i] = dkgi
	}

	//Share distribution phase
	distributionPhaseResponses := make([]*dkg.Response, 0, n*n)
	for _, dkgInstance := range dkgs {
		deals, err := dkgInstance.Deals()
		if err != nil {
			return nil, err
		}
		//Each party verify their deal and broadcast a response
		for i, d := range deals {
			resp, err := dkgs[i].ProcessDeal(d)
			if err != nil {
				return nil, err
			}
			distributionPhaseResponses = append(distributionPhaseResponses, resp)
		}
	}

	justifications := make([]*dkg.Justification, 0)
	for _, resp := range distributionPhaseResponses {
		for i, dkgInstance := range dkgs {
			if resp.Response.Index == uint32(i) {
				continue
			}
			j, err := dkgInstance.ProcessResponse(resp)
			if err != nil {
				return nil, err
			}
			if j != nil {
				justifications = append(justifications, j)
				fmt.Printf("Justification by %v participant", i)
			}
		}
	}

	//process justification
	for _, j := range justifications {
		for _, dkgInstance := range dkgs {
			err := dkgInstance.ProcessJustification(j)
			if err != nil {
				return nil, err
			}
		}
	}

	//each participant verify that he is certified
	var qual []int
	for i, dkgInstance := range dkgs {
		if !dkgInstance.Certified() {
			fmt.Printf("Praticipant %v is not certified", i)
		} else {
			//all honest participant have the same QUAL-set
			if qual == nil {
				qual = dkgInstance.QUAL()
			}
		}
	}

	//each party publishes unmasked commit
	complaints := make([]*dkg.ComplaintCommits, 0)
	secCommits := make(map[int]*dkg.SecretCommits)
	for _, idx := range qual {
		commit, err := dkgs[idx].SecretCommits()
		if err != nil {
			return nil, err
		}
		secCommits[idx] = commit
		for _, idx := range qual {
			complaint, err := dkgs[idx].ProcessSecretCommits(commit)
			if err != nil {
				return nil, err
			}
			if complaint != nil {
				complaints = append(complaints, complaint)
			}
		}
	}

	//complaints processing
	recMessages := make([]*dkg.ReconstructCommits, 0)
	for _, idx := range qual {
		for _, comp := range complaints {
			reconstructionMessage, err := dkgs[idx].ProcessComplaintCommits(comp)
			if err != nil {
				return nil, err
			}
			if reconstructionMessage != nil {
				recMessages = append(recMessages, reconstructionMessage)
			}
		}
	}

	//reconstruction malicious participants polynomials
	for _, idx := range qual {
		for _, reconstructionMessage := range recMessages {
			err := dkgs[idx].ProcessReconstructCommits(reconstructionMessage)
			if err != nil {
				return nil, err
			}
		}
	}

	for _, idx := range qual {
		if !dkgs[idx].Finished() {
			return nil, errors.New("Participant isn't finished")
		}
	}

	return dkgs, nil
}

func ElGamalEncrypt(group kyber.Group, pubkey kyber.Point, message []byte) (
	ct elgamal.Ciphertext, remainder []byte, M kyber.Point) {
	M = group.Point().Embed(message, random.New())
	max := group.Point().EmbedLen()
	if max > len(message) {
		max = len(message)
	}
	remainder = message[max:]
	k := group.Scalar().Pick(random.New())
	S := group.Point().Mul(k, pubkey)
	ct = elgamal.Ciphertext{group.Point().Mul(k, nil), S.Add(S, M)}
	return
}

func PublishDecryptShare(group kyber.Group, C elgamal.Ciphertext, secretShare kyber.Scalar) (
	D kyber.Point) {
	D = group.Point().Mul(secretShare, C.PointA)
	return
}

//func ElGamalDecrypt(group kyber.Group, prikey kyber.Scalar, K, C kyber.Point) (
//message []byte, err error) {
//S := group.Point().Mul(prikey, K)
//M := group.Point().Sub(C, S)
//message, err = M.Data()
//return
//}
func main() {
	suite := nist.NewBlakeSHA256P256()
	t := 4
	n := 10
	parties, err := DKG(suite, n, t)
	if err != nil {
		println("DKG Error")
		println(err)
		return
	}
	distKeyShares := make([]*dkg.DistKeyShare, n)
	for i, p := range parties {
		keyShare, err := p.DistKeyShare()
		if err != nil {
			println(err)
			return
		}
		distKeyShares[i] = keyShare
	}
	share, _ := parties[0].DistKeyShare()
	publicKey := share.Public()
	allC := make([]elgamal.Ciphertext, len(parties))
	realM := suite.Point().Null()
	var Mi kyber.Point
	for i := 0; i < len(parties); i++ {
		m := []byte("JOPKA")
		allC[i], _, Mi = ElGamalEncrypt(suite, publicKey, m)
		realM = suite.Point().Add(realM, Mi)
	}
	C := elgamal.AggregateCiphertext(suite, allC)
	D := make([]kyber.Point, t)
	for i := 0; i < t; i++ {
		D[i] = PublishDecryptShare(suite, C, distKeyShares[i].PriShare().V)
	}
	randM := elgamal.Decrypt(suite, C, D, t, n)
	fmt.Println(randM.Equal(realM))
	//	mm, err := ElGamalDecrypt(suite, a, K, C)
	//	if err != nil {
	//		fmt.Println("decryption failed: " + err.Error())
	//	}
	//	if string(mm) != string(m) {
	//		fmt.Println("decryption produced wrong output: " + string(mm))
	//	}
	//	fmt.Println("Decryption succeeded: " + string(mm))
}
