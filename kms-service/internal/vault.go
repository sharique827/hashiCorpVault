package internal

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
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

// FetchKEK retrieves the KEK for a project from Vault.
func (vc *VaultClient) FetchKEK(project string) ([]byte, error) {
	ctx := context.Background()
	secret, err := vc.Client.KVv2("secret").Get(ctx, project)
	if err != nil {
		return nil, err
	}
	kekB64, ok := secret.Data["kek"].(string)
	if !ok {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(kekB64)
}

// EncryptWithAESGCM encrypts plaintext with the given key using AES-GCM.
func EncryptWithAESGCM(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// DecryptWithAESGCM decrypts ciphertext with the given key and nonce using AES-GCM.
func DecryptWithAESGCM(key, ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}
