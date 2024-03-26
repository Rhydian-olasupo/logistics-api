package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"go_trial/gorest/models"

	"github.com/golang-jwt/jwt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type DB struct {
	Collection *mongo.Collection
}

var secretKey = []byte(os.Getenv("session_secret"))
var (
	mongoClient *mongo.Client
	dbName      = "apiDB"
	collection  = "logistics"
)

type Response struct {
	Token string `json:"token" bson:"token"`
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
func (db *DB) LoginTokenHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Please poass the data in URL encoded form", http.StatusBadRequest)
		return
	}

	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")

	// MongoDB client and context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// MongoDB collection instance
	collection := mongoClient.Database(dbName).Collection(collection)

	// Find the user by username
	var user struct {
		Password string `bson:"password"`
	}
	err = collection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if password != user.Password {
		http.Error(w, "Invalid Password", http.StatusUnauthorized)
		return
	}

	// Password is correct, generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"iat":      time.Now().Unix(),
	})
	tokenString, err := token.SignedString([]byte("your_secret_key"))
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Token generated successfully, send it in the response
	response := Response{Token: tokenString}
	respJSON, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respJSON)
}
