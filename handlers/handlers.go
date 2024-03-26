package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"go_trial/gorest/models"

	"go.mongodb.org/mongo-driver/mongo"
)

type DB struct {
	Collection *mongo.Collection
}

//CreateUserhandler handles requests to create new user

func (db *DB) CreateUserhandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Request Body:", r.Body)
	// Declare a variable to hold the new user
	var newUser models.User

	// Read the request body
	postBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Decode the JSON request body into newUser struct
	if err := json.Unmarshal(postBody, &newUser); err != nil {
		http.Error(w, "Error decoding JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Insert the new user into the database
	result, err := db.Collection.InsertOne(context.TODO(), newUser)
	if err != nil {
		http.Error(w, "Failed to create user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Prepare the response
	response := map[string]interface{}{
		"message":     "User created successfully",
		"inserted_id": result.InsertedID,
	}

	// Encode the response as JSON and send it
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Error encoding response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}
