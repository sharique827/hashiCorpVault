package internal

import (
	"encoding/json"
	"log"
	"net/http"

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

		var apiKey string

		// Check Redis for existing API key for this project
		if cache != nil {
			apiKey, _ = cache.Client.Get(r.Context(), req.Project+":api_key").Result()
		}

		// If not found in Redis, check DB
		if apiKey == "" && db != nil {
			apiKey, _ = db.GetAPIKeyByProject(req.Project)
		}

		// If still not found, generate a new API key
		if apiKey == "" {
			apiKey = uuid.NewString()
			if err := db.InsertRequest(req.Name, req.Project, req.Team, req.Email, apiKey); err != nil {
				log.Printf("DB error: %v", err)
				http.Error(w, "DB error", http.StatusInternalServerError)
				return
			}
			if cache != nil {
				cache.Client.Set(r.Context(), req.Project+":api_key", apiKey, 0)
				cache.Client.Set(r.Context(), apiKey, req.Project, 0)
			}
			// Create Transit key for project via KMS
			if err := KMSCreateKey(req.Project); err != nil {
				log.Printf("KMS key creation failed: %v", err)
				http.Error(w, "Failed to create project key in KMS", http.StatusInternalServerError)
				return
			}
		}

		resp := RegisterResponse{APIKey: apiKey}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
