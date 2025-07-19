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
func CreateInvoiceHandler(db *InvoiceDB, mainDB *DB, cache *Cache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Get API key from header
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			http.Error(w, "Missing API key", http.StatusUnauthorized)
			return
		}

		// 2. Validate API key (cache, then DB)
		var project string
		var err error
		if cache != nil {
			project, _ = cache.Client.Get(r.Context(), apiKey).Result()
		}
		if project == "" && mainDB != nil {
			project, err = mainDB.GetProjectByAPIKey(apiKey)
			if err != nil || project == "" {
				http.Error(w, "Invalid API key", http.StatusUnauthorized)
				return
			}
		}

		// 3. Parse request and check project match
		var req InvoiceRequest
		body, _ := ioutil.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		if req.Project != project {
			http.Error(w, "API key does not match project", http.StatusUnauthorized)
			return
		}

		// 4. Now fetch KEK, encrypt, and save
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
func FetchInvoiceHandler(db *InvoiceDB, mainDB *DB, cache *Cache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Get API key from header
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			http.Error(w, "Missing API key", http.StatusUnauthorized)
			return
		}

		// 2. Validate API key (cache, then DB)
		var project string
		var err error
		if cache != nil {
			project, _ = cache.Client.Get(r.Context(), apiKey).Result()
		}
		if project == "" && mainDB != nil {
			project, err = mainDB.GetProjectByAPIKey(apiKey)
			if err != nil || project == "" {
				http.Error(w, "Invalid API key", http.StatusUnauthorized)
				return
			}
		}

		// 3. Parse request and check project match
		var req InvoiceFetchRequest
		body, _ := ioutil.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		if req.Project != project {
			http.Error(w, "API key does not match project", http.StatusUnauthorized)
			return
		}

		// 4. Fetch KEK for the project
		kek, _, err := FetchKEKFromVault(r.Context(), req.Project)
		if err != nil {
			http.Error(w, "Failed to fetch KEK", http.StatusInternalServerError)
			return
		}
		defer ZeroBytes(kek)

		// 5. Retrieve invoice record
		rec, err := db.GetInvoice(req.Project, req.InvoiceID)
		if err != nil {
			http.Error(w, "Invoice not found", http.StatusNotFound)
			return
		}

		// 6. Decrypt EDEK to get DEK, then decrypt data
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
