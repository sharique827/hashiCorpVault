package main

import (
	"kms-service/internal"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/create-key", internal.CreateKeyHandler()).Methods("POST")
	r.HandleFunc("/wrap-dek", internal.WrapDEKHandler()).Methods("POST")
	r.HandleFunc("/unwrap-dek", internal.UnwrapDEKHandler()).Methods("POST")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}
	log.Printf("KMS service running on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
