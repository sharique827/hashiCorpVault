package internal

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"

	vaultapi "github.com/hashicorp/vault/api"
)

type VaultClient struct {
	Client *vaultapi.Client
}

func InitVault() (*VaultClient, error) {
	config := vaultapi.DefaultConfig()
	config.Address = os.Getenv("VAULT_ADDR")
	client, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, err
	}
	client.SetToken(os.Getenv("VAULT_TOKEN"))
	return &VaultClient{Client: client}, nil
}

func (vc *VaultClient) StoreKEK(project string, kek []byte) error {
	ctx := context.Background()
	data := map[string]interface{}{
		"data": map[string]interface{}{
			"kek": base64.StdEncoding.EncodeToString(kek),
		},
	}
	_, err := vc.Client.KVv2("secret").Put(ctx, project, data["data"].(map[string]interface{}))
	return err
}

func GenerateRandomKEK() ([]byte, error) {
	kek := make([]byte, 32) // 256 bits
	_, err := rand.Read(kek)
	return kek, err
}
