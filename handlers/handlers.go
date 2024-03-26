package handlers

import (
	"encoding/json"
	"net/http"

	"go_trial/gorest/models"

	"go.mongodb.org/mongo-driver/mongo"
)

type DB struct {
	collection *mongo.Collection
}

//CreateUserhandler handles requests to create new user

func CreateUserhandler(w http.ResponseWriter, r *http.Request) {
	var newUser models.User
	err := json.NewDecoder(r.Body).Decode(&newUser)
}
