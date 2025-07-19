package internal

import (
	"bytes"
	"encoding/base64"
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

// For envelope encryption

type WrapDEKRequest struct {
	Project string `json:"project"`
	DEK     string `json:"dek"`
}

type WrapDEKResponse struct {
	EDEK  string `json:"edek"`
	Nonce string `json:"nonce"`
}

type UnwrapDEKRequest struct {
	Project string `json:"project"`
	EDEK    string `json:"edek"`
	Nonce   string `json:"nonce"`
}

type UnwrapDEKResponse struct {
	DEK string `json:"dek"`
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

func CallKMSWrapDEK(project string, dek []byte) (edek, nonce []byte, err error) {
	url := os.Getenv("KMS_URL") + "/wrap-dek"
	body, _ := json.Marshal(WrapDEKRequest{
		Project: project,
		DEK:     base64.StdEncoding.EncodeToString(dek),
	})
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	var kmsResp WrapDEKResponse
	if err := json.NewDecoder(resp.Body).Decode(&kmsResp); err != nil {
		return nil, nil, err
	}
	edek, err = base64.StdEncoding.DecodeString(kmsResp.EDEK)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = base64.StdEncoding.DecodeString(kmsResp.Nonce)
	if err != nil {
		return nil, nil, err
	}
	return edek, nonce, nil
}

func CallKMSUnwrapDEK(project string, edek, nonce []byte) (dek []byte, err error) {
	url := os.Getenv("KMS_URL") + "/unwrap-dek"
	body, _ := json.Marshal(UnwrapDEKRequest{
		Project: project,
		EDEK:    base64.StdEncoding.EncodeToString(edek),
		Nonce:   base64.StdEncoding.EncodeToString(nonce),
	})
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var kmsResp UnwrapDEKResponse
	if err := json.NewDecoder(resp.Body).Decode(&kmsResp); err != nil {
		return nil, err
	}
	dek, err = base64.StdEncoding.DecodeString(kmsResp.DEK)
	if err != nil {
		return nil, err
	}
	return dek, nil
}
