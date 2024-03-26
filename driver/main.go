package main

import (
	"context"
	"go_trial/gorest/handlers"
	"go_trial/gorest/utils"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

func main() {
	// Initialize MongoDB client
	client, err := utils.InitMongoClient()
	if err != nil {
		panic(err)
	}
	defer client.Disconnect(context.TODO())

	// Get database collection
	collection := utils.GetCollection(client, "apiDB", "logistics")

	// Create an instance of your DB
	db := &handlers.DB{Collection: collection}
	r := mux.NewRouter()

	//Attach middleware to handle request validation

	//r.Use(middleware.ValidateRequestBody)

	// Define routes
	r.HandleFunc("/api/users", db.CreateUserhandler).Methods("POST")
	r.HandleFunc("/token/login/", db.LoginTokenHandler).Methods("POST")

	srv := &http.Server{
		Handler:      r,
		Addr:         "127.0.0.1:8000",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}
