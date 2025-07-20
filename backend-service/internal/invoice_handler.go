package internal

import (
	"encoding/json"
	"io/ioutil"
	"log"
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
		// Wrap DEK with KMS
		edek, err := KMSWrapDEK(req.Project, dek)
		if err != nil {
			http.Error(w, "Failed to wrap DEK", http.StatusInternalServerError)
			return
		}
		// Ensure dekNonce is never nil (set to empty slice)
		dekNonce := []byte{}
		if err := db.InsertInvoice(req.Project, req.InvoiceID, []byte(edek), encryptedData, dekNonce, dataNonce, "v1"); err != nil {
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
		log.Printf("API key: %s, resolved project: %s", apiKey, project)
		log.Printf("Request body: project=%s, invoice_id=%s", req.Project, req.InvoiceID)
		if req.Project != project {
			http.Error(w, "API key does not match project", http.StatusUnauthorized)
			return
		}
		// Debug: print all invoice rows
		rows, _ := db.Pool.Query(r.Context(), "SELECT id, project, invoice_id FROM invoice")
		for rows.Next() {
			var id int
			var p, invID string
			rows.Scan(&id, &p, &invID)
			log.Printf("Invoice row: id=%d, project=%s, invoice_id=%s", id, p, invID)
		}
		rec, err := db.GetInvoice(req.Project, req.InvoiceID)
		if err != nil {
			log.Printf("DB lookup failed for project=%s, invoice_id=%s, error=%v", req.Project, req.InvoiceID, err)
			http.Error(w, "Invoice not found", http.StatusNotFound)
			return
		}
		// Unwrap DEK with KMS
		dek, err := KMSUnwrapDEK(req.Project, string(rec.EDEK))
		if err != nil {
			http.Error(w, "Failed to unwrap DEK", http.StatusInternalServerError)
			return
		}
		log.Printf("Decrypting with DEK len=%d, Encrypted len=%d, Nonce len=%d", len(dek), len(rec.Encrypted), len(rec.DataNonce))
		plain, err := DecryptWithAESGCM(dek, rec.Encrypted, rec.DataNonce)
		if err != nil {
			http.Error(w, "Decryption failed", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(InvoiceFetchResponse{InvoiceID: req.InvoiceID, Data: string(plain)})
	}
}
