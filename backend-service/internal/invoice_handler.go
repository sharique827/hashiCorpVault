package internal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"

	vaultapi "github.com/hashicorp/vault/api"
)

type InvoiceRequest struct {
	Project   string `json:"project"`
	InvoiceID string `json:"invoice_id"`
	Data      string `json:"data"` // plaintext invoice data
}

type InvoiceResponse struct {
	InvoiceID string `json:"invoice_id"`
	Status    string `json:"status"`
}

type InvoiceFetchRequest struct {
	Project   string `json:"project"`
	InvoiceID string `json:"invoice_id"`
}

type InvoiceFetchResponse struct {
	InvoiceID string `json:"invoice_id"`
	Data      string `json:"data"` // decrypted plaintext
}

// Handler to create encrypted invoice
func CreateInvoiceHandler(db *InvoiceDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req InvoiceRequest
		body, _ := ioutil.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		// Fetch KEK from Vault
		kek, keyVersion, err := FetchKEKFromVault(r.Context(), req.Project)
		if err != nil {
			http.Error(w, "Failed to fetch KEK", http.StatusInternalServerError)
			return
		}
		defer ZeroBytes(kek)
		// Envelope encrypt
		encryptedData, edek, dekNonce, dataNonce, err := EnvelopeEncrypt([]byte(req.Data), kek)
		if err != nil {
			http.Error(w, "Encryption failed", http.StatusInternalServerError)
			return
		}
		if err := db.InsertInvoice(req.Project, req.InvoiceID, edek, encryptedData, dekNonce, dataNonce, keyVersion); err != nil {
			http.Error(w, "DB insert failed", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(InvoiceResponse{InvoiceID: req.InvoiceID, Status: "stored"})
	}
}

// Handler to fetch and decrypt invoice
func FetchInvoiceHandler(db *InvoiceDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req InvoiceFetchRequest
		body, _ := ioutil.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		rec, err := db.GetInvoice(req.Project, req.InvoiceID)
		if err != nil {
			http.Error(w, "Invoice not found", http.StatusNotFound)
			return
		}
		// Fetch KEK from Vault
		kek, _, err := FetchKEKFromVault(r.Context(), req.Project)
		if err != nil {
			http.Error(w, "Failed to fetch KEK", http.StatusInternalServerError)
			return
		}
		defer ZeroBytes(kek)
		plain, err := EnvelopeDecrypt(rec.Encrypted, rec.EDEK, kek, rec.DEKNonce, rec.DataNonce)
		if err != nil {
			http.Error(w, "Decryption failed", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(InvoiceFetchResponse{InvoiceID: req.InvoiceID, Data: string(plain)})
	}
}

// FetchKEKFromVault fetches the KEK and key version for a project from Vault
func FetchKEKFromVault(ctx context.Context, project string) (kek []byte, keyVersion string, err error) {
	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultToken := os.Getenv("VAULT_TOKEN")
	config := vaultapi.DefaultConfig()
	config.Address = vaultAddr
	client, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, "", err
	}
	client.SetToken(vaultToken)
	secret, err := client.KVv2("secret").Get(ctx, project)
	if err != nil {
		return nil, "", err
	}
	kekStr, ok := secret.Data["kek"].(string)
	if !ok {
		return nil, "", errors.New("KEK not found in Vault")
	}
	kek, err = base64.StdEncoding.DecodeString(kekStr)
	if err != nil {
		return nil, "", err
	}
	keyVersion = "v1"
	return kek, keyVersion, nil
}

// ZeroBytes securely zeroes a byte slice
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
