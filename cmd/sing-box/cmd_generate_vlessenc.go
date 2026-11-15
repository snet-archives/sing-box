package main

import (
	"encoding/json"
	"os"

	"github.com/sagernet/sing-box/common/vlessenc"
	"github.com/sagernet/sing-box/log"

	"github.com/spf13/cobra"
)

var commandGenerateVLESSKeyPair = &cobra.Command{
	Use:   "vless-keypair",
	Short: "Generate VLESS hybrid X25519 + ML-KEM-768 encryption key pair",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if err := generateVLESSKeyPair(); err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandGenerate.AddCommand(commandGenerateVLESSKeyPair)
}

func generateVLESSKeyPair() error {
	kp, err := vlessenc.GenerateKeyPair()
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(kp, "", "  ")
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(encoded, '\n'))
	return err
}
