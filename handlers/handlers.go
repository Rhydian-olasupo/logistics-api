package handlers

import (
	"context"
	"encoding/json"
	"net/http"

	"go_trial/gorest/models"

	"go.mongodb.org/mongo-driver/mongo"
)

type DB struct {
	collection *mongo.Collection
}

//CreateUserhandler handles requests to create new user

func (db *DB) CreateUserhandler(w http.ResponseWriter, r *http.Request) {
	var newUser models.User
	if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
		http.Error(w, "Invalid Request Body", http.StatusBadRequest)
		return
	}

	// Insert the new user into the database
	result, err := db.collection.InsertOne(context.TODO(), newUser)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Respond with success message
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"message":     "User created successfully",
		"inserted_id": result.InsertedID,
	}
	json.NewEncoder(w).Encode(response)
}
