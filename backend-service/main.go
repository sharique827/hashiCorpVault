package main

import (
	"backend-service/internal"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, relying on environment variables")
	}

	db, err := internal.InitDB()
	if err != nil {
		log.Fatalf("Failed to connect to DB: %v", err)
	}
	defer db.Close()

	cache, err := internal.InitCache()
	if err != nil {
		log.Printf("Redis not available: %v", err)
	}

	invoiceDB := &internal.InvoiceDB{Pool: db.Pool}

	r := mux.NewRouter()
	r.HandleFunc("/register", internal.RegisterHandler(db, cache)).Methods("POST")
	r.HandleFunc("/invoice/create", internal.CreateInvoiceHandler(invoiceDB, db, cache)).Methods("POST")
	r.HandleFunc("/invoice/fetch", internal.FetchInvoiceHandler(invoiceDB, db, cache)).Methods("POST")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Backend service running on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
