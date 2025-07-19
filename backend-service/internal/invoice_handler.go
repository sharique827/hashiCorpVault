package internal

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
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
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			http.Error(w, "Missing API key", http.StatusUnauthorized)
			return
		}
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
		// Generate DEK, encrypt data
		dek, err := GenerateDEK()
		if err != nil {
			http.Error(w, "Failed to generate DEK", http.StatusInternalServerError)
			return
		}
		encryptedData, dataNonce, err := EncryptWithAESGCM(dek, []byte(req.Data))
		if err != nil {
			http.Error(w, "Encryption failed", http.StatusInternalServerError)
			return
		}
		// Wrap DEK with Vault Transit
		edek, err := VaultTransitEncryptDEK(req.Project, dek)
		if err != nil {
			http.Error(w, "Failed to wrap DEK", http.StatusInternalServerError)
			return
		}
		// Store encryptedData, edek, dataNonce
		if err := db.InsertInvoice(req.Project, req.InvoiceID, []byte(edek), encryptedData, nil, dataNonce, "v1"); err != nil {
			http.Error(w, "DB insert failed", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(InvoiceResponse{InvoiceID: req.InvoiceID, Status: "stored"})
	}
}

// Handler to fetch and decrypt invoice
func FetchInvoiceHandler(db *InvoiceDB, mainDB *DB, cache *Cache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			http.Error(w, "Missing API key", http.StatusUnauthorized)
			return
		}
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
		rec, err := db.GetInvoice(req.Project, req.InvoiceID)
		if err != nil {
			http.Error(w, "Invoice not found", http.StatusNotFound)
			return
		}
		// Unwrap DEK with Vault Transit
		dek, err := VaultTransitDecryptDEK(req.Project, string(rec.EDEK))
		if err != nil {
			http.Error(w, "Failed to unwrap DEK", http.StatusInternalServerError)
			return
		}
		plain, err := DecryptWithAESGCM(dek, rec.Encrypted, rec.DataNonce)
		if err != nil {
			http.Error(w, "Decryption failed", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(InvoiceFetchResponse{InvoiceID: req.InvoiceID, Data: string(plain)})
	}
}
