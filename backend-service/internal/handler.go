package internal

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/google/uuid"
)

type RegisterRequest struct {
	Name    string `json:"name"`
	Project string `json:"project"`
	Team    string `json:"team"`
	Email   string `json:"email"`
}

type RegisterResponse struct {
	APIKey string `json:"api_key"`
}

func RegisterHandler(db *DB, cache *Cache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		apiKey := uuid.NewString()
		if err := db.InsertRequest(req.Name, req.Project, req.Team, req.Email, apiKey); err != nil {
			log.Printf("DB error: %v", err)
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		if cache != nil {
			cache.Client.Set(r.Context(), apiKey, req.Project, 0)
		}
		// Create Transit key for project
		vaultAddr := os.Getenv("VAULT_ADDR")
		vaultToken := os.Getenv("VAULT_TOKEN")
		url := vaultAddr + "/v1/transit/keys/" + req.Project + "-kek"
		payload := map[string]interface{}{"type": "aes256-gcm96"}
		body, _ := json.Marshal(payload)
		reqVault, _ := http.NewRequest("POST", url, bytes.NewBuffer(body))
		reqVault.Header.Set("X-Vault-Token", vaultToken)
		reqVault.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(reqVault)
		if err != nil || (resp.StatusCode != 200 && resp.StatusCode != 204) {
			log.Printf("Vault Transit key creation failed: %v", err)
			http.Error(w, "Failed to create project key in Vault", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(RegisterResponse{APIKey: apiKey})
	}
}
