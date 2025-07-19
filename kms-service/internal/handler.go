package internal

import (
	"encoding/json"
	"net/http"
)

type KEKRequest struct {
	Project string `json:"project"`
}

type KEKResponse struct {
	Status string `json:"status"`
}

func GenerateKEKHandler(vc *VaultClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KEKRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Project == "" {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		kek, err := GenerateRandomKEK()
		if err != nil {
			http.Error(w, "Failed to generate KEK", http.StatusInternalServerError)
			return
		}
		if err := vc.StoreKEK(req.Project, kek); err != nil {
			http.Error(w, "Failed to store KEK", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(KEKResponse{Status: "ACK"})
	}
}
