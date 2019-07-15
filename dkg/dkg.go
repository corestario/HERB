package dkg

import (
"errors"
"fmt"
"sync"

"go.dedis.ch/kyber/v3"
"go.dedis.ch/kyber/v3/suites"
"go.dedis.ch/kyber/v3/util/key"

"go.dedis.ch/kyber/v3/share"
dkg "go.dedis.ch/kyber/v3/share/dkg/rabin"
)

//RabinDKGSimulator generates n DistKeyGenerator objects which can generate DistKeyShare
//DistKeyShare contains secret and public keys
func RabinDKGSimulator(suiteName string, n int, t int) ([]*dkg.DistKeyShare, []*kyber.Point, error) {
	suite, findErr := suites.Find(suiteName)

	if findErr != nil {
		return nil, nil, findErr
	}

	//Each party generate their own master secret key and corresponding public key. This secret key will become a shared key.
	secretKeys, publicKeys := personalKeyGen(suite, n)

	//Each party creates they own copy of RabinDKGSimulator-object
	dkgs := make([]*dkg.DistKeyGenerator, n)
	for i := 0; i < n; i++ {
		dkgi, err := dkg.NewDistKeyGenerator(suite, secretKeys[i], publicKeys, t)
		if err != nil {
			return nil, nil, err
		}
		dkgs[i] = dkgi
	}

	//Share distribution phase
	distributionPhaseResponses, distDealErr := dealsDistributionAndProcessing(dkgs, n)
	if distDealErr != nil {
		return nil, nil, distDealErr
	}

	justificationErr := JustificationPhase(dkgs, distributionPhaseResponses)
	if justificationErr != nil {
		return nil, nil, justificationErr
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
	complaints, unmaskErr := UnmaskedCommitesDist(dkgs, qual)
	if unmaskErr != nil {
		return nil, nil, unmaskErr
	}

	complaintErr := ComplaintProcessing(dkgs, qual, complaints)
	if complaintErr != nil {
		return nil, nil, complaintErr
	}

	for _, idx := range qual {
		if !dkgs[idx].Finished() {
			return nil, nil, errors.New("Participant isn't finished")
		}
	}

	distShares := make([]*dkg.DistKeyShare, len(qual))

	for i, dkgInstance := range dkgs {
		keyShare, err := dkgInstance.DistKeyShare()
		if err != nil {
			return nil, nil, err
		}
		distShares[i] = keyShare
	}

	verificationKeys := make([]*kyber.Point, len(qual))
	pubPoly := share.NewPubPoly(suite, nil, distShares[0].Commitments())
	for i, keyShare := range distShares {
		verificationKey := pubPoly.Eval(keyShare.PriShare().I)
		if verificationKey == nil {
			return nil, nil, errors.New("Verification key equal nil")
		}
		verificationKeys[i] = &verificationKey.V
	}
	return distShares, verificationKeys, nil
}

type generatedKeyPair struct {
	id      int
	keyPair *key.Pair
}

//personalKeyGen generates n key pairs for n parcticipant.
//Generated key pairs split into two arrays: secretKeys and publicKeys
//In "real" system each participant should generate key.NewKeyPair and publish Public part of this keyPair
func personalKeyGen(suite suites.Suite, n int) ([]kyber.Scalar, []kyber.Point) {
	secretKeys := make([]kyber.Scalar, n)
	publicKeys := make([]kyber.Point, n)
	generatedPairs := make(chan generatedKeyPair, n)
	wg := sync.WaitGroup{}

	go func() {
		wg.Add(n)

		for i := 0; i < n; i++ {
			go func(id int) {
				///////////// MAIN PART ///////////
				keyPair := key.NewKeyPair(suite)
				///////////// \MAIN PART //////////
				generatedPairs <- generatedKeyPair{id, keyPair}
				wg.Done()
			}(i)
		}

		wg.Wait()
		close(generatedPairs)
	}()

	for pair := range generatedPairs {
		secretKeys[pair.id] = pair.keyPair.Private
		publicKeys[pair.id] = pair.keyPair.Public
	}

	return secretKeys, publicKeys
}

func dealsDistributionAndProcessing(dkgs []*dkg.DistKeyGenerator, n int) ([]*dkg.Response, error) {
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

	return distributionPhaseResponses, nil
}

func UnmaskedCommitesDist(dkgs []*dkg.DistKeyGenerator, qual []int) ([]*dkg.ComplaintCommits, error) {
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

	return complaints, nil
}

func JustificationPhase(dkgs []*dkg.DistKeyGenerator, responses []*dkg.Response) error {
	justifications := make([]*dkg.Justification, 0)
	for _, resp := range responses {
		for i, dkgInstance := range dkgs {
			if resp.Response.Index == uint32(i) {
				continue
			}
			j, err := dkgInstance.ProcessResponse(resp)
			if err != nil {
				return err
			}
			if j != nil {
				justifications = append(justifications, j)
			}
		}
	}

	//process justification
	for _, j := range justifications {
		for _, dkgInstance := range dkgs {
			err := dkgInstance.ProcessJustification(j)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func ComplaintProcessing(dkgs []*dkg.DistKeyGenerator, qual []int, complaints []*dkg.ComplaintCommits) error {
	recMessages := make([]*dkg.ReconstructCommits, 0)
	for _, idx := range qual {
		for _, comp := range complaints {
			reconstructionMessage, err := dkgs[idx].ProcessComplaintCommits(comp)
			if err != nil {
				return err
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
				return err
			}
		}
	}
	return nil
}