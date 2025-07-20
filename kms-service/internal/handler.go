package internal

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

type CreateKeyRequest struct {
	Project string `json:"project"`
}

type CreateKeyResponse struct {
	Status string `json:"status"`
}

type WrapDEKRequest struct {
	Project string `json:"project"`
	DEK     string `json:"dek"`
}

type WrapDEKResponse struct {
	EDEK string `json:"edek"`
}

type UnwrapDEKRequest struct {
	Project string `json:"project"`
	EDEK    string `json:"edek"`
}

type UnwrapDEKResponse struct {
	DEK string `json:"dek"`
}

// CreateVaultTransitKey creates a new transit key for the given project in Vault
func CreateVaultTransitKey(project string) error {
	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultToken := os.Getenv("VAULT_TOKEN")
	url := vaultAddr + "/v1/transit/keys/" + project + "-kek"
	payload := map[string]string{"type": "aes256-gcm96"}
	body, _ := json.Marshal(payload)
	log.Printf("Calling Vault to create transit key: POST %s", url)
	reqVault, _ := http.NewRequest("POST", url, bytes.NewBuffer(body))
	reqVault.Header.Set("X-Vault-Token", vaultToken)
	reqVault.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(reqVault)
	if err != nil {
		log.Printf("Error making request to Vault: %v", err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		respBody, _ := ioutil.ReadAll(resp.Body)
		log.Printf("Vault returned status %d: %s", resp.StatusCode, string(respBody))
		return err
	}
	return nil
}

func CreateKeyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received /create-key request")
		var req CreateKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		// Call Vault to create a transit key for the project
		err := CreateVaultTransitKey(req.Project)
		if err != nil {
			log.Printf("Error creating Vault transit key: %v", err)
			http.Error(w, "Failed to create key in Vault", http.StatusInternalServerError)
			return
		}
		resp := CreateKeyResponse{Status: "ACK"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func WrapDEKHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received /wrap-dek request")
		var req WrapDEKRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Project == "" || req.DEK == "" {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		vaultAddr := os.Getenv("VAULT_ADDR")
		vaultToken := os.Getenv("VAULT_TOKEN")
		url := vaultAddr + "/v1/transit/encrypt/" + req.Project + "-kek"
		payload := map[string]string{"plaintext": req.DEK}
		body, _ := json.Marshal(payload)
		reqVault, _ := http.NewRequest("POST", url, bytes.NewBuffer(body))
		reqVault.Header.Set("X-Vault-Token", vaultToken)
		reqVault.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(reqVault)
		if err != nil {
			log.Printf("Error making request to Vault: %v", err)
			http.Error(w, "Failed to wrap DEK", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
		respBody, _ := ioutil.ReadAll(resp.Body)
		log.Printf("Vault /encrypt response: %s", string(respBody))
		var vaultResp struct {
			Data struct {
				Ciphertext string `json:"ciphertext"`
			} `json:"data"`
		}
		if err := json.Unmarshal(respBody, &vaultResp); err != nil {
			log.Printf("Error unmarshaling Vault response: %v", err)
			http.Error(w, "Invalid Vault response", http.StatusInternalServerError)
			return
		}
		if vaultResp.Data.Ciphertext == "" {
			log.Printf("Vault did not return a ciphertext!")
		}
		json.NewEncoder(w).Encode(WrapDEKResponse{EDEK: vaultResp.Data.Ciphertext})
	}
}

func UnwrapDEKHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req UnwrapDEKRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Project == "" || req.EDEK == "" {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		vaultAddr := os.Getenv("VAULT_ADDR")
		vaultToken := os.Getenv("VAULT_TOKEN")
		url := vaultAddr + "/v1/transit/decrypt/" + req.Project + "-kek"
		payload := map[string]string{"ciphertext": req.EDEK}
		body, _ := json.Marshal(payload)
		reqVault, _ := http.NewRequest("POST", url, bytes.NewBuffer(body))
		reqVault.Header.Set("X-Vault-Token", vaultToken)
		reqVault.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(reqVault)
		if err != nil {
			http.Error(w, "Failed to unwrap EDEK", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
		respBody, _ := ioutil.ReadAll(resp.Body)
		var vaultResp struct {
			Data struct {
				Plaintext string `json:"plaintext"`
			} `json:"data"`
		}
		if err := json.Unmarshal(respBody, &vaultResp); err != nil {
			http.Error(w, "Invalid Vault response", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(UnwrapDEKResponse{DEK: vaultResp.Data.Plaintext})
	}
}
