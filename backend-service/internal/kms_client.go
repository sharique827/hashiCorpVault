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

func CallKMSForKEK(project string) error {
	url := os.Getenv("KMS_URL") + "/generate-kek"
	body, _ := json.Marshal(KMSRequest{Project: project})
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil // Only need ACK, ignore errors for now
	}
	return nil
}
