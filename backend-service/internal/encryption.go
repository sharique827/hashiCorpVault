package internal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
)

// GenerateDEK generates a new random 256-bit DEK.
func GenerateDEK() ([]byte, error) {
	dek := make([]byte, 32) // 256 bits
	_, err := rand.Read(dek)
	return dek, err
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
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
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

// KMS API helpers
func KMSCreateKey(project string) error {
	url := os.Getenv("KMS_URL") + "/create-key"
	body, _ := json.Marshal(map[string]string{"project": project})
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func KMSWrapDEK(project string, dek []byte) (string, error) {
	url := os.Getenv("KMS_URL") + "/wrap-dek"
	body, _ := json.Marshal(map[string]string{
		"project": project,
		"dek":     base64.StdEncoding.EncodeToString(dek),
	})
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var respData struct {
		EDEK string `json:"edek"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return "", err
	}
	return respData.EDEK, nil
}

func KMSUnwrapDEK(project string, edek string) ([]byte, error) {
	url := os.Getenv("KMS_URL") + "/unwrap-dek"
	body, _ := json.Marshal(map[string]string{
		"project": project,
		"edek":    edek,
	})
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var respData struct {
		DEK string `json:"dek"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(respData.DEK)
}
