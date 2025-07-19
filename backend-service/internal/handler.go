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
		apiKey := uuid.NewString()
		if err := db.InsertRequest(req.Name, req.Project, req.Team, req.Email, apiKey); err != nil {
			log.Printf("DB error: %v", err)
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		if cache != nil {
			cache.Client.Set(r.Context(), apiKey, req.Project, 0)
		}
		if status, err := CallKMSForKEK(req.Project); err != nil || status != "ACK" {
			log.Printf("KMS error or NACK: %v, status: %s", err, status)
			// Continue, as per requirements
		}
		json.NewEncoder(w).Encode(RegisterResponse{APIKey: apiKey})
	}
}
