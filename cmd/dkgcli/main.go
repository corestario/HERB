package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/tendermint/tendermint/libs/cli"

	app "github.com/dgamingfoundation/HERB"
	"github.com/dgamingfoundation/HERB/x/herb"
	"github.com/dgamingfoundation/HERB/dkg"
	"github.com/spf13/cobra"

	"go.dedis.ch/kyber/v3"
	kyberenc "go.dedis.ch/kyber/v3/util/encoding"
)

func main() {
	cobra.EnableCommandSorting = false

	rootCmd := &cobra.Command{
		Use: "dkg",
		Short: "Distributed Key Generation simulator for HERB",
	}

	rootCmd.AddCommand(generateKeyFile(app.DefaultDKGHome))

	// prepare and add flags
	executor := cli.PrepareBaseCmd(rootCmd, "HERB", app.DefaultDKGHome)
	err := executor.Execute()
	if err != nil {
		panic(err)
	}
}

func generateKeyFile(defaultDKGHome string) *cobra.Command {
	return &cobra.Command{
		Use: "gen-key-file [t] [n]",
		Short: "generates JSON key file which contains keys for (t, n)-threshold cryptosystem",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {

			t, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("t (%s) not a valid int, please input a valid number", args[0])
			}
			if t <= 0 {
				return fmt.Errorf("t (%s) must be positive", args[0])
			}

			n, err := strconv.ParseInt(args[1], 10, 64)
			if err != nil {
				return fmt.Errorf("n (%s) not a valid int, please input a valid number", args[1])
			}
			if n <= 0 {
				return fmt.Errorf("n (%s) must be positive", args[1])
			}

			commonKey, keyHolders, err := generateKeys(int(t), int(n))
			if err != nil {
				return fmt.Errorf("failed generating keys: %v", err)
			}

			commonKeyStr, err := kyberenc.PointToStringHex(herb.P256, commonKey)
			if err != nil {
				return fmt.Errorf("common key serialization failed: %v ", err)
			}

			khJSON, err := serializeKeyHolders(keyHolders)
			if err != nil {
				return fmt.Errorf("partial keys serialization failed: %v ", err)
			}

			res := keyGenResult{
				CommonKey:   commonKeyStr,
				PartialKeys: khJSON,
			}

			resJSON, err := json.Marshal(res)
			if err != nil {
				return fmt.Errorf("results marshalling failed: %v", err)
			}

			os.Mkdir(defaultDKGHome, 0777)
			path := defaultDKGHome + "/keys.json"
			file, err := os.Create(path)
			if err != nil {
				return fmt.Errorf("creating file failed: %v", err)
			}
			defer file.Close()
			file, err = os.OpenFile(path, os.O_RDWR, 0644)
			if err != nil {
				return fmt.Errorf("opening file failed: %v", err)
			}

			_, err = file.Write(resJSON)
			if err != nil {
				return fmt.Errorf("writing to the file failed: %v", err)
			}

			err = file.Sync()
			if err != nil {
				return fmt.Errorf("writing to the file failed: %v", err)
			}

			return nil
		},
	}
}

type keyGenResult struct {
	CommonKey   string          `json:"common_key"`
	PartialKeys []keyHolderJSON `json:"partial_keys"`
}

type keyHolder struct {
	ID int64
	PrivateKey kyber.Scalar
	VerificationKey kyber.Point
}

type keyHolderJSON struct {
	ID string `json:id`
	PrivateKeyHex string `json:"private_key"`
	VerificationKeyHex string `json:"verification_key"`
}

func generateKeys(t int, n int) (kyber.Point, []keyHolder, error) {
	group := herb.P256
	parties, _, err := dkg.RabinDKGSimulator("P256", n, t)
	if err != nil {
		return nil, nil, err
	}
	commonKey := parties[0].Public()
	keyHolders := make([]keyHolder, n)
	for i, p := range parties {
		keyHolders[i] = keyHolder{
			ID: int64(p.PriShare().I),
			PrivateKey: p.PriShare().V,
			VerificationKey: group.Point().Mul(p.PriShare().V, nil),
		}
	}
	return commonKey, keyHolders, nil
}

func serializeKeyHolders(keyHolders []keyHolder) ([]keyHolderJSON, error) {
	group := herb.P256
	khJSON := make([]keyHolderJSON, len(keyHolders))
	for i := range keyHolders {
		var err error
		khJSON[i].ID = strconv.FormatInt(keyHolders[i].ID, 10)
		khJSON[i].PrivateKeyHex, err = kyberenc.ScalarToStringHex(group, keyHolders[i].PrivateKey)
		if err != nil {
			return nil, err
		}
		khJSON[i].VerificationKeyHex, err = kyberenc.PointToStringHex(group, keyHolders[i].VerificationKey)
		if err != nil {
			return nil, err
		}
	}
	return khJSON, nil
}