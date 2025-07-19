package internal

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
)

type KMSRequest struct {
	Project string `json:"project"`
}

type KMSResponse struct {
	Status string `json:"status"`
}

func CallKMSForKEK(project string) (string, error) {
	url := os.Getenv("KMS_URL") + "/generate-kek"
	body, _ := json.Marshal(KMSRequest{Project: project})
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return "NACK", err
	}
	defer resp.Body.Close()

	var kmsResp KMSResponse
	if err := json.NewDecoder(resp.Body).Decode(&kmsResp); err != nil {
		return "NACK", err
	}

	if kmsResp.Status == "ACK" {
		return "ACK", nil
	}
	return "NACK", nil
}
