package main

import (
	"log"
	"net/http"
	"os"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"kms-service/internal"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, relying on environment variables")
	}

	vaultClient, err := internal.InitVault()
	if err != nil {
		log.Fatalf("Failed to connect to Vault: %v", err)
	}

	r := mux.NewRouter()
	r.HandleFunc("/generate-kek", internal.GenerateKEKHandler(vaultClient)).Methods("POST")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}
	log.Printf("KMS service running on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
