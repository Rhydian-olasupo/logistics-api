package main

import (
	"context"
	"go_trial/gorest/handlers"
	_ "go_trial/gorest/middleware"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		panic(err)
	}

	defer client.Disconnect(context.TODO())
	collection := client.Database("apiDB").Collection("logistics")

	// Create an instance of your DB
	db := &handlers.DB{Collection: collection}
	r := mux.NewRouter()

	//Attach middleware to handle request validation

	//r.Use(middleware.ValidateRequestBody)

	// Define routes
	r.HandleFunc("/api/users", db.CreateUserhandler).Methods("POST")

	srv := &http.Server{
		Handler:      r,
		Addr:         "127.0.0.1:8000",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}
