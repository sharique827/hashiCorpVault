package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// GenerateDEK generates a new random 256-bit DEK.
func GenerateDEK() ([]byte, error) {
	dek := make([]byte, 32) // 256 bits
	_, err := rand.Read(dek)
	return dek, err
}

// EncryptWithAESGCM encrypts plaintext with the given key using AES-GCM.
func EncryptWithAESGCM(key, plaintext []byte) (ciphertext, nonce, tag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	// AES-GCM appends the tag to the ciphertext
	return ct, nonce, nil, nil
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
	pt, err := gcm.Open(nil, nonce, ciphertext, nil)
	return pt, err
}

// EnvelopeEncrypt encrypts data with a DEK, then encrypts the DEK with the KEK (from Vault).
func EnvelopeEncrypt(plainData, kek []byte) (encryptedData, edek, dekNonce, dataNonce []byte, err error) {
	dek, err := GenerateDEK()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// Encrypt the data with the DEK
	encryptedData, dataNonce, _, err = EncryptWithAESGCM(dek, plainData)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// Encrypt the DEK with the KEK (envelope)
	edek, dekNonce, _, err = EncryptWithAESGCM(kek, dek)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// Zero DEK from memory
	for i := range dek {
		dek[i] = 0
	}
	return encryptedData, edek, dekNonce, dataNonce, nil
}

// EnvelopeDecrypt decrypts EDEK with KEK to get DEK, then decrypts data with DEK.
func EnvelopeDecrypt(encryptedData, edek, kek, dekNonce, dataNonce []byte) ([]byte, error) {
	dek, err := DecryptWithAESGCM(kek, edek, dekNonce)
	if err != nil {
		return nil, err
	}
	plainData, err := DecryptWithAESGCM(dek, encryptedData, dataNonce)
	// Zero DEK from memory
	for i := range dek {
		dek[i] = 0
	}
	return plainData, err
}
