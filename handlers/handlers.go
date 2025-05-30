package handlers

// Package handlers provides HTTP handler functions for the logistics API.
// It includes functions for handling requests, processing data, and interacting
// with the database. The package also integrates with various third-party
// libraries for JWT authentication, routing, metrics collection, and telemetry.help create the folder and the files
//
// The following libraries are imported:
// - context: for managing request contexts.
// - encoding/json: for encoding and decoding JSON data.
// - fmt: for formatted I/O operations.
// - io: for basic I/O operations.
// - log: for logging messages.
// - net/http: for HTTP client and server implementations.
// - os: for interacting with the operating system.
// - strconv: for converting strings to other types.
// - time: for time-related functions.
// - go_trial/gorest/models: for data models.
// - go_trial/gorest/utils: for utility functions.
// - github.com/golang-jwt/jwt: for JWT authentication.
// - github.com/gorilla/mux: for HTTP request routing.
// - github.com/prometheus/client_golang/prometheus: for metrics collection.
// - go.mongodb.org/mongo-driver/bson: for BSON encoding and decoding.
// - go.mongodb.org/mongo-driver/bson/primitive: for MongoDB primitive types.
// - go.mongodb.org/mongo-driver/mongo: for MongoDB client and server interactions.
// - go.opentelemetry.io/otel: for OpenTelemetry integration.
// - golang.org/x/crypto/bcrypt: for password hashing.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"go_trial/gorest/models"
	"go_trial/gorest/utils"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stripe/stripe-go/v72"
	"github.com/stripe/stripe-go/v72/charge"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.opentelemetry.io/otel"
	"golang.org/x/crypto/bcrypt"
)

type DB struct {
	Collection *mongo.Collection
	// TokenCollection          *mongo.Collection
	MenuItemCollection       *mongo.Collection
	UserGroup                *mongo.Collection
	CategoryCollection       *mongo.Collection
	CartCollection           *mongo.Collection
	OrderItemCollection      *mongo.Collection
	OrdersCollection         *mongo.Collection
	RefreshTokenCollection   *mongo.Collection
	TokenBlacklistCollection *mongo.Collection
	AuditLogCollection       *mongo.Collection
}

// type contextKey string

// var (
// 	USERNAME contextKey
// 	USERROLE contextKey
// )

// Save user with flat structure
type UserFlat struct {
	ID           interface{} `json:"id" bson:"_id,omitempty"`
	Name         string      `json:"name" bson:"name"`
	Email        string      `json:"email" bson:"email"`
	PasswordHash string      `json:"password" bson:"password"`
}

var secretKey = []byte(os.Getenv("session_secret"))

type Response struct {
	AccessToken  string `json:"token" bson:"token"`
	RefreshToken string `json:"refresh_token" bson:"refresh_token"`
}

// Define Prometheus metrics
var (
	// Counter for the number of requests
	requestCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "create_user_requests_total",
			Help: "Total number of requests to create user",
		},
		[]string{"status"}, // Label for status (e.g., success, error)
	)

	// Histogram for request duration
	requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "create_user_duration_seconds",
			Help:    "Histogram of request durations for creating user",
			Buckets: prometheus.DefBuckets, // Default buckets
		},
		[]string{"status"}, // Label for status (e.g., success, error)
	)

	// Counter for the number of  login requests
	loginRequests = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "login_requests_total",
		Help: "Total number of login requests",
	})

	loginRequestsbyStatus = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "login_requests_by_status_total",
		Help: "Total number of login requests by status",
	},
		[]string{"status"})
)

func Init() {
	// Register metrics with Prometheus
	prometheus.MustRegister(requestCount)
	prometheus.MustRegister(requestDuration)
	prometheus.MustRegister(loginRequests)
	prometheus.MustRegister(loginRequestsbyStatus)
}

//CreateUserhandler handles requests to create new user

func (db *DB) CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	// Start the request duration timer
	start := time.Now()

	// Start tracing (OpenTelemetry)
	ctx, span := otel.Tracer("auth-service").Start(r.Context(), "CreateUserhandler")
	defer span.End()

	var newUser models.User

	// Decode request body
	_, decodeSpan := otel.Tracer("auth_service").Start(ctx, "Decoding request body")
	decodeSpan.End()


	if err := r.ParseForm(); err != nil {
		decodeSpan.RecordError(err)
		http.Error(w, "Error parsing form data: "+err.Error(), http.StatusBadRequest)
		// Increment error counter and record duration
		requestCount.WithLabelValues("error").Inc()
		requestDuration.WithLabelValues("error").Observe(time.Since(start).Seconds())
		return
	}

	newUser.Name = r.FormValue("name")
	newUser.Email = r.FormValue("email")
	newUser.Password = r.FormValue("password")

	if newUser.Name == "" || newUser.Email == "" || newUser.Password == "" {
		http.Error(w, "All fields (name, email, password) are required", http.StatusBadRequest)
		// Increment error counter and record duration
		requestCount.WithLabelValues("error").Inc()
		requestDuration.WithLabelValues("error").Observe(time.Since(start).Seconds())
		return
	}

	// Validate the required fields
	if newUser.Name == "" || newUser.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		// Increment error counter and record duration
		requestCount.WithLabelValues("error").Inc()
		requestDuration.WithLabelValues("error").Observe(time.Since(start).Seconds())
		return
	}

	// Check if the username already exists
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var existingUser struct {
		Name string `bson:"name"`
	}
	err := db.Collection.FindOne(ctx, bson.M{"name": newUser.Name}).Decode(&existingUser)
	if err != nil && err != mongo.ErrNoDocuments {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		// Increment error counter and record duration
		requestCount.WithLabelValues("error").Inc()
		requestDuration.WithLabelValues("error").Observe(time.Since(start).Seconds())
		return
	}

	// If a user with the same name exists, return an error
	if existingUser.Name == newUser.Name {
		http.Error(w, "Username is already taken", http.StatusBadRequest)
		// Increment error counter and record duration
		requestCount.WithLabelValues("error").Inc()
		requestDuration.WithLabelValues("error").Observe(time.Since(start).Seconds())
		return
	}

	// Hash the user's password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password: "+err.Error(), http.StatusInternalServerError)
		// Increment error counter and record duration
		requestCount.WithLabelValues("error").Inc()
		requestDuration.WithLabelValues("error").Observe(time.Since(start).Seconds())
		return
	}

	// Prepare the user object to insert into the database
	user := UserFlat{
		Name:         newUser.Name,
		Email:        newUser.Email,
		PasswordHash: string(passwordHash),
	}

	// Insert the new user into the database
	result, err := db.Collection.InsertOne(ctx, user)
	if err != nil {
		http.Error(w, "Failed to create user: "+err.Error(), http.StatusInternalServerError)
		// Increment error counter and record duration
		requestCount.WithLabelValues("error").Inc()
		requestDuration.WithLabelValues("error").Observe(time.Since(start).Seconds())
		return
	}

	// Send success response
	response := map[string]interface{}{
		"message":     "User created successfully",
		"inserted_id": result.InsertedID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Error encoding response: "+err.Error(), http.StatusInternalServerError)
		// Increment error counter and record duration
		requestCount.WithLabelValues("error").Inc()
		requestDuration.WithLabelValues("error").Observe(time.Since(start).Seconds())
		return
	}

	// Increment success counter and record duration
	requestCount.WithLabelValues("success").Inc()
	requestDuration.WithLabelValues("success").Observe(time.Since(start).Seconds())
}

func (db *DB) LoginTokenHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodPost {
		loginRequests.Inc()
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Invalid Form Data", http.StatusBadRequest)
			loginRequestsbyStatus.WithLabelValues("Error").Inc()
			return
		}

		username := r.PostForm.Get("name")
		password := r.PostForm.Get("password")

		if username == "" || password == "" {
			http.Error(w, "Username and Password are required", http.StatusBadRequest)
			return
		}

		// MongoDB client and context
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var user UserFlat

		err = db.Collection.FindOne(ctx, bson.M{"name": username}).Decode(&user)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				http.Error(w, "User not Found", http.StatusNotFound)
				loginRequestsbyStatus.WithLabelValues("Error").Inc()
				return
			}
			http.Error(w, "Database Error", http.StatusInternalServerError)
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
			http.Error(w, "Invalid Credentials", http.StatusBadRequest)
			loginRequestsbyStatus.WithLabelValues("Error").Inc()
			return
		}

		// Password is correct, generate JWT token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": username,
			"exp":      time.Now().Add(time.Hour * 1).Unix(), // Access token expires in 1 hour
			"iat":      time.Now().Unix(),
		})
		tokenString, err := token.SignedString([]byte(secretKey))
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			loginRequestsbyStatus.WithLabelValues("Error").Inc()
			return
		}

		//Generate Refresh Token
		refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": username,
			"exp":      time.Now().Add(24 * time.Hour).Unix(), // Refresh token expires in 24 hours
			"iat":      time.Now().Unix(),
			"type":     "refresh",
		})

		refreshTokenString, err := refreshToken.SignedString([]byte(secretKey))
		if err != nil {
			http.Error(w, "Failed to generate token "+err.Error(), http.StatusInternalServerError)
			loginRequestsbyStatus.WithLabelValues("Error").Inc()
			return
		}

		//Store refresh token in the database
		_, err = db.RefreshTokenCollection.InsertOne(ctx, bson.M{
			"username":     user.Name,
			"refreshToken": refreshTokenString,
			"iat":          time.Now().Unix(),
		})
		if err != nil {
			http.Error(w, "Failed to store refresh Token"+err.Error(), http.StatusInternalServerError)
			loginRequestsbyStatus.WithLabelValues("Error")
			return
		}

		// Token generated successfully, send it in the response
		response := Response{AccessToken: tokenString, RefreshToken: refreshTokenString}
		respJSON, err := json.Marshal(response)
		if err != nil {
			http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(respJSON)
		loginRequestsbyStatus.WithLabelValues("success").Inc()
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		loginRequestsbyStatus.WithLabelValues("Error").Inc()
		return
	}
}

func (db *DB) RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if request.RefreshToken == "" {
		http.Error(w, "Refresh token is required", http.StatusBadRequest)
		return
	}

	token, err := jwt.Parse(request.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected sigining method: %v", token.Header["alg"])
		}

		return []byte(secretKey), nil

	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}
	if claims["type"] != "refresh" {
		http.Error(w, "Invalid token type", http.StatusUnauthorized)
		return
	}

	username, ok := claims["username"].(string)
	if !ok {
		http.Error(w, "Invalid token payload", http.StatusUnauthorized)
		return
	}

	// Check if the refresh token exists in the database
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var storedToken struct {
		RefreshToken string `json:"refreshToken" bson:"refreshToken"`
	}

	err = db.RefreshTokenCollection.FindOne(ctx, bson.M{
		"username":     username,
		"refreshToken": request.RefreshToken,
	}).Decode(&storedToken)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Refresh token not found", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Generate a new access token
	newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(1 * time.Hour).Unix(),
		"iat":      time.Now().Unix(),
	})

	newAccessTokenString, err := newAccessToken.SignedString([]byte(secretKey))
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	// Optionally, generate a new refresh token and replace the old one -- TODO

	// Send the new access token in the response
	response := struct {
		AccessToken string `json:"access_token"`
	}{
		AccessToken: newAccessTokenString,
	}

	respJSON, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respJSON)
}

//LogoutUserhandler handles requests to logout user

func (db *DB) LogoutUserHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve username from context
	username, ok := r.Context().Value("username").(string)
	if !ok {
		http.Error(w, "Failed to retrieve username", http.StatusInternalServerError)
		return
	}

	// MongoDB client and context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	//Blacklist the access token

	accessToken := r.Header.Get("token")

	if accessToken != "" {
		blacklistToken := bson.M{"token": accessToken, "expiresAt": time.Now().Add(time.Second * 60).Unix()}
		_, err := db.TokenBlacklistCollection.InsertOne(ctx, blacklistToken)
		if err != nil {
			http.Error(w, "Failed to blacklist token", http.StatusInternalServerError)
			return
		}
	}

	// Delete refresh token from the database
	result, err := db.RefreshTokenCollection.DeleteOne(ctx, bson.M{"username": username})
	if err != nil {
		http.Error(w, "Failed to delete refresh token", http.StatusInternalServerError)
		return
	}

	if result.DeletedCount == 0 {
		http.Error(w, "No active session found", http.StatusNotFound)
		return
	}

	//Log the logut operation for auditing

	logoutLog := bson.M{"username": username, "timestamp": time.Now().Unix(), "operation": "logout", "ip": r.RemoteAddr}

	_, err = db.AuditLogCollection.InsertOne(ctx, logoutLog)

	if err != nil {
		http.Error(w, "Failed to log the logout operation", http.StatusInternalServerError)
		return
	}

	// Send success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User logged out successfully"})

}

func (db *DB) GetCurrentUserHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve username from context
	username, _ := r.Context().Value("username").(string)

	// Query database for user details
	var user models.SingleUser
	err := db.Collection.FindOne(context.TODO(), bson.M{"name": username}).Decode(&user)
	if err != nil {
		// Handle errors (e.g., user not found)
		if err == mongo.ErrNoDocuments {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("User not found"))
			return
		}
		http.Error(w, "Error fetching user details", http.StatusInternalServerError)
		return
	}

	// Respond with user details
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

// Handler for assigning users to groups
func (db *DB) AssignGroupHandler(w http.ResponseWriter, r *http.Request) {
	// Decode JSON request body
	var req struct {
		Name  string `json:"name" bson:"name"`
		Group string `json:"group" bson:"group"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Update user's group in the database
	_, err := db.UserGroup.InsertOne(context.TODO(), bson.M{"name": req.Name, "group": req.Group})
	if err != nil {
		http.Error(w, "Failed to assign group to user", http.StatusInternalServerError)
		return
	}

	// Respond with success message
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User assigned to group successfully"})
}

func (db *DB) ManageMangersHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		//Get request from all Managers
		db.GetAllManagersHandler(w, r)
	case http.MethodPost:
		db.assignUserToManagerHandler(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (db *DB) ManageDeliveryHanlder(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		//Get request from all delivery crew
		db.GetAllDeliveryCrewHandler(w, r)
	case http.MethodPost:
		db.assignUsertoDeliveryCrewHandler(w, r)
	default:
		http.Error(w, "Method nt allowed", http.StatusMethodNotAllowed)
	}
}

func (db *DB) GetAllDeliveryCrewHandler(w http.ResponseWriter, r *http.Request) {
	//Define a slice to store all delivery crew
	var DeliveryCrew []struct {
		Name  string `json:"name" bson:"name"`
		Group string `json:"group" bson:"group"`
	}

	//Find all documents where group is "Delivery Crew"
	cursor, err := db.UserGroup.Find(context.TODO(), bson.M{"group": "Delivery Crew"})
	if err != nil {
		http.Error(w, "Failed to fetch Delivery Crews", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	//Iterate over the cursor and decode each document
	for cursor.Next(context.TODO()) {
		var delivery_crew struct {
			Name  string `json:"name" bson:"name"`
			Group string `json:"group" bson:"group"`
		}

		if err := cursor.Decode(&delivery_crew); err != nil {
			http.Error(w, "Failed to decode delivery crew", http.StatusInternalServerError)
			return
		}

		DeliveryCrew = append(DeliveryCrew, delivery_crew)
	}

	if err := cursor.Err(); err != nil {
		http.Error(w, "Error while iterating over Delivery Crews", http.StatusInternalServerError)
		return
	}

	//Encode the resutl as JSON and write to response
	jsonBytes, err := json.Marshal(DeliveryCrew)
	if err != nil {
		http.Error(w, " Failed to encode Delivery Crew to JSON", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonBytes)
}

func (db *DB) GetAllManagersHandler(w http.ResponseWriter, r *http.Request) {
	// Define a slice to store multiple managers
	var managers []struct {
		Name  string `json:"name" bson:"name"`
		Group string `json:"group" bson:"group"`
	}

	// Find all documents where group is "Manager"
	cursor, err := db.UserGroup.Find(context.TODO(), bson.M{"group": "Manager"})
	if err != nil {
		http.Error(w, "Failed to fetch managers", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	// Iterate over the cursor and decode each document
	for cursor.Next(context.TODO()) {
		var manager struct {
			Name  string `json:"name" bson:"name"`
			Group string `json:"group" bson:"group"`
		}
		if err := cursor.Decode(&manager); err != nil {
			http.Error(w, "Failed to decode manager", http.StatusInternalServerError)
			return
		}
		managers = append(managers, manager)
	}
	if err := cursor.Err(); err != nil {
		http.Error(w, "Error while iterating over managers", http.StatusInternalServerError)
		return
	}

	// Encode the result as JSON and write to response
	jsonBytes, err := json.Marshal(managers)
	if err != nil {
		http.Error(w, "Failed to encode managers to JSON", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonBytes)
}

func (db *DB) assignUserToManagerHandler(w http.ResponseWriter, r *http.Request) {
	userRole := r.Context().Value("userrole").(string)
	switch userRole {
	case "Manager":
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Please pass the data in a form format", http.StatusInternalServerError)
			return
		}
		username := r.PostForm.Get("username")
		if username == "" {
			http.Error(w, "Username is required", http.StatusInternalServerError)
		}
		var existingUser struct {
			Name  string `json:"name" bson:"name"`
			Group string `json:"group" bson:"group"`
		}
		if err = db.UserGroup.FindOne(context.Background(), bson.M{"name": username}).Decode(&existingUser); err == nil {
			http.Error(w, "User already exists as a delivery crew", http.StatusBadRequest)
			return
		} else {
			_, err = db.UserGroup.InsertOne(context.TODO(), bson.M{"name": username, "group": "Manager"})
			if err != nil {
				http.Error(w, "Failed to assign to Delivery Crew", http.StatusBadRequest)
				return
			}
		}
		// Send a success reponse
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

func (db *DB) assignUsertoDeliveryCrewHandler(w http.ResponseWriter, r *http.Request) {
	userRole := r.Context().Value("userRole").(string)
	switch userRole {
	case "Manager":
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Please pass the data in a form format", http.StatusInternalServerError)
			return
		}
		username := r.PostForm.Get("username")
		if username == "" {
			http.Error(w, "Username is required", http.StatusInternalServerError)
		}
		var existingUser struct {
			Name  string `json:"name" bson:"name"`
			Group string `json:"group" bson:"group"`
		}
		if err = db.UserGroup.FindOne(context.Background(), bson.M{"name": username}).Decode(&existingUser); err == nil {
			http.Error(w, "User already exists as a delivery crew", http.StatusBadRequest)
			return
		} else {
			_, err = db.UserGroup.InsertOne(context.TODO(), bson.M{"name": username, "group": "Delivery Crew"})
			if err != nil {
				http.Error(w, "Failed to assign to Delivery Crew", http.StatusBadRequest)
				log.Printf("Failed to assign to Delivery Crew: %v", err)
				return
			}
		}
		// Send a success reponse
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}

}

// Delete the user from the Group they belong
// There is a better way to write this, I will come back to this.
func (db *DB) DeleteManagerHandler(w http.ResponseWriter, r *http.Request) {
	userRole := r.Context().Value("userRole").(string)
	switch userRole {
	case "Manager":
		vars := mux.Vars(r)
		group := "Manager"
		var data struct {
			Group string `json:"group" bson:"group"`
		}
		objectID, _ := primitive.ObjectIDFromHex(vars["id"])
		if err := db.UserGroup.FindOne(context.TODO(), bson.M{"_id": objectID}).Decode(&data); err != nil {
			http.Error(w, "User ID not Found", http.StatusNotFound)
			return
		} else {
			if data.Group != group {
				http.Error(w, "Cant Delete User as it does not belong in the Manager Group", http.StatusBadRequest)
				return
			} else {
				filter := bson.M{"_id": objectID}
				_, err := db.UserGroup.DeleteOne(context.TODO(), filter)
				if err != nil {
					log.Println("Cant delete database record")
				}
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"message": "User deleted from manager group successfully"})
		}
	default:
		http.Error(w, "Unauthorized", http.StatusUnauthorized)

	}

}

func (db *DB) DeleteDeliveryHandler(w http.ResponseWriter, r *http.Request) {
	userRole := r.Context().Value("userRole").(string)
	switch userRole {
	case "Manager":
		vars := mux.Vars(r)
		group := "Delivery Crew"
		var data struct {
			Group string `json:"group" bson:"group"`
		}
		objectID, _ := primitive.ObjectIDFromHex(vars["id"])
		if err := db.UserGroup.FindOne(context.TODO(), bson.M{"_id": objectID}).Decode(&data); err != nil {
			http.Error(w, "User ID not Found", http.StatusNotFound)
			return
		} else {
			if data.Group != group {
				http.Error(w, "Cant Delete User as it does not belong in the Delivery Group", http.StatusBadRequest)
				return
			} else {
				filter := bson.M{"_id": objectID}
				_, err := db.UserGroup.DeleteOne(context.TODO(), filter)
				if err != nil {
					log.Println("Cant delte database record")
				}
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"message": "User deleted from delivery group successfully"})
		}
	default:
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

func (db *DB) PostItemCategory(w http.ResponseWriter, r *http.Request) {
	var category models.Category
	postBody, _ := io.ReadAll(r.Body)
	json.Unmarshal(postBody, &category)
	result, err := db.CategoryCollection.InsertOne(context.TODO(), category)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	} else {
		w.Header().Set("Content-Type", "application/json")
		response, _ := json.Marshal(result)
		w.WriteHeader(http.StatusOK)
		w.Write(response)
	}
}

func (db *DB) GetAllItemCategories(w http.ResponseWriter, r *http.Request) {
	var categories []models.Category

	cursor, err := db.CategoryCollection.Find(context.TODO(), bson.M{})
	if err != nil {
		http.Error(w, "Failed to fetch categories", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	// Iterate over the cursor and decode each document
	for cursor.Next(context.TODO()) {
		var category models.Category
		if err := cursor.Decode(&category); err != nil {
			http.Error(w, "Failed to decode category", http.StatusInternalServerError)
			return
		}
		categories = append(categories, category)
	}
	if err := cursor.Err(); err != nil {
		http.Error(w, "Error while iterating over categories", http.StatusInternalServerError)
		return
	}

	// Encode the result as JSON and write to response
	jsonBytes, err := json.Marshal(categories)
	if err != nil {
		http.Error(w, "Failed to encode managers to JSON", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonBytes)
}

func (db *DB) ManageMenuHanlder(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		db.GetMenuItems(w, r)
	case http.MethodPost:
		db.PostMenuItems(w, r)
	}
}

func (db *DB) PostMenuItems(w http.ResponseWriter, r *http.Request) {
	userRole := r.Context().Value("userRole").(string)
	switch userRole {
	case "Manager":
		var menuitem models.MenuItem
		postBody, _ := io.ReadAll(r.Body)
		//This is me using the categoryID but it should be the category name/title. Refactor later
		var categoryID primitive.ObjectID
		menuitem.Category = categoryID
		json.Unmarshal(postBody, &menuitem)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result, err := db.MenuItemCollection.InsertOne(ctx, menuitem)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
		} else {
			w.Header().Set("Content-Type", "application/json")
			reponse, _ := json.Marshal(result)
			w.WriteHeader(http.StatusOK)
			w.Write(reponse)
		}
	default:
		http.Error(w, "Unathorized....", http.StatusUnauthorized)
	}
}

// GET request handler to retrieve all menu items with category information
func (db *DB) GetMenuItems(w http.ResponseWriter, r *http.Request) {
	// Default pagination parameters
	defaultPageSize := 5
	defaultPage := 1

	//Calculate pagination parameters
	pageSize := defaultPageSize
	page := defaultPage

	//Calculate skip count
	skip := (page - 1) * pageSize
	type MenuItemWithCategory struct {
		models.MenuItem `bson:",inline"`
		Category        models.Category `json:"category" bson:"category"`
	}

	menuItemsWithCategory := []MenuItemWithCategory{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Perform a lookup or join operation to fetch category information for each menu item
	cursor, err := db.MenuItemCollection.Aggregate(ctx, mongo.Pipeline{
		bson.D{
			{Key: "$lookup", Value: bson.D{
				{Key: "from", Value: "Category"},       // Name of the collection to lookup, incase this is the category collection
				{Key: "localField", Value: "category"}, // Field in the local collection to match,this means value to look for from the document in the collection
				{Key: "foreignField", Value: "_id"},    // Field in the foreign collection to match, the foreign key  to the Menuitem collection
				{Key: "as", Value: "category"},         // Alias for the joined field in the output documents
			}},
		},
		bson.D{
			{Key: "$unwind", Value: "$category"},
		},
		//Pagination: Skip records and limit number of records
		bson.D{{Key: "$skip", Value: skip}},
		bson.D{{Key: "$limit", Value: pageSize}},
	})
	if err != nil {
		http.Error(w, "Failed to retrieve menu items", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var menuItemWithCategory MenuItemWithCategory
		if err := cursor.Decode(&menuItemWithCategory); err != nil {
			http.Error(w, "Failed to decode menu items", http.StatusInternalServerError)
			return
		}
		menuItemsWithCategory = append(menuItemsWithCategory, menuItemWithCategory)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(menuItemsWithCategory)
}

// Function to delete menu items from the menu collection
func (db *DB) DeleteSingleMenuItem(w http.ResponseWriter, r *http.Request) {
	userRole := r.Context().Value("userRole").(string)
	fmt.Println(userRole)
	switch userRole {
	case "Manager":
		vars := mux.Vars(r)
		objectID, _ := primitive.ObjectIDFromHex(vars["id"])
		filter := bson.M{"_id": objectID}
		_, err := db.MenuItemCollection.DeleteOne(context.TODO(), filter)
		if err != nil {
			http.Error(w, "Cannot delete database record", http.StatusBadRequest)
		}

	default:
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}

}

func (db *DB) GetSingleleMenuItem(w http.ResponseWriter, r *http.Request) {
	userRole := r.Context().Value("userRole").(string)
	fmt.Println(userRole)
	var singleItem models.MenuItem
	vars := mux.Vars(r)
	//Still getting with ID , should be getting with name
	objectID, _ := primitive.ObjectIDFromHex(vars["id"])
	filter := bson.M{"_id": objectID}
	err := db.MenuItemCollection.FindOne(context.TODO(), filter).Decode(&singleItem)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	} else {
		w.Header().Set("Content-Type", "application/json")
		response, _ := json.Marshal(singleItem)
		w.WriteHeader(http.StatusOK)
		w.Write(response)
	}
}

func (db *DB) PutSingleMenuItem(w http.ResponseWriter, r *http.Request) {
	userRole := r.Context().Value("userRole").(string)
	fmt.Println(userRole)
	vars := mux.Vars(r)
	id, _ := primitive.ObjectIDFromHex(vars["id"])

	switch userRole {
	case "Manager":
		var menuItem models.MenuItem
		if err := json.NewDecoder(r.Body).Decode(&menuItem); err != nil {
			http.Error(w, "FAILURE TO DECODE JSON BDOY", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := db.MenuItemCollection.ReplaceOne(ctx, bson.M{"_id": id}, menuItem)
		if err != nil {
			http.Error(w, "Failed to update menu item", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}

}

// PATCH request handler to partially update an existing menu item
func (db *DB) PatchMenuItems(w http.ResponseWriter, r *http.Request) {
	userRole := r.Context().Value("userRole").(string)
	fmt.Println(userRole)
	vars := mux.Vars(r)
	id, _ := primitive.ObjectIDFromHex(vars["id"])
	switch userRole {
	case "Manager":
		var updateData bson.M
		if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
			http.Error(w, "Failed to decode request body", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := db.MenuItemCollection.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": updateData})
		if err != nil {
			http.Error(w, "Failed to update menu item", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Unauthrized", http.StatusUnauthorized)
	}

}

func (db *DB) ManageSingleItemHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		db.PutSingleMenuItem(w, r)
	case http.MethodGet:
		db.GetSingleleMenuItem(w, r)
	case http.MethodDelete:
		db.DeleteSingleMenuItem(w, r)
	case http.MethodPatch:
		db.PatchMenuItems(w, r)
	}
}

// Cart Management endpoints
func (db *DB) PostMenuItemstoCart(w http.ResponseWriter, r *http.Request) {
	// Retrieve username from context
	username, ok := r.Context().Value("username").(string)
	if !ok {
		http.Error(w, "Failed to retrieve username", http.StatusInternalServerError)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Please pass the data in URL form encoded", http.StatusBadRequest)
		return
	}

	// Extract form values
	quantityStr := r.PostForm.Get("quantity")
	menuItem := r.PostForm.Get("menuitem")

	//Get unit price from title
	unitprice, err := getUnitPriceFromTitle(menuItem)
	if err != nil {
		http.Error(w, "Cannot get unit price", http.StatusInternalServerError)
	}

	// Convert string values to appropriate types
	quantity, err := strconv.ParseInt(quantityStr, 10, 16)
	if err != nil {
		http.Error(w, "Invalid quantity", http.StatusBadRequest)
		return
	}
	// Calculate the price
	//Float the unit price not the quantity -- Fix
	price := float64(quantity) * unitprice

	// Get the user ID from the username
	userIDStr, err := getUserIDFromUsername(username)
	if err != nil {
		http.Error(w, "Failed to retrieve user ID", http.StatusInternalServerError)
		return
	}
	// Convert the user ID string to primitive.ObjectID
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return

	}

	// Create a new Cart instance
	cart := models.Cart{
		User:      userID, // Use the user ID
		MenuItem:  menuItem,
		Quantity:  int16(quantity),
		UnitPrice: unitprice,
		Price:     price,
	}

	// Insert the cart item into the database
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = db.CartCollection.InsertOne(ctx, cart)
	if err != nil {
		http.Error(w, "Failed to add menu item to cart", http.StatusInternalServerError)
		return
	}

	// Respond with the ID of the newly inserted cart item
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Menu Item added to Cart successfully"})
	// json.NewEncoder(w).Encode(result.InsertedID)
}

func getUserIDFromUsername(username string) (string, error) {
	// Establish MongoDB connection with context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // Adjust timeout as needed
	defer cancel()

	client, err := utils.InitMongoClient()
	if err != nil {
		return "", fmt.Errorf("error initializing MongoDB client: %w", err)
	}
	defer client.Disconnect(ctx)

	// Get collection reference
	IDCollection := utils.GetCollection(client, "apiDB", "logistics")

	// Query and decode result
	var result struct {
		ID primitive.ObjectID `json:"id" bson:"_id"`
	}
	err = IDCollection.FindOne(ctx, bson.M{"name": username}).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return "", fmt.Errorf("ID not found for username: %s", username)
		}
		return "", fmt.Errorf("error finding ID: %w", err) // Wrap errors for better handling
	}

	// Convert ObjectID to hexadecimal string
	userID := result.ID.Hex()

	return userID, nil
}

func getUnitPriceFromTitle(menuTitle string) (float64, error) {
	//Establish mongoDB connection with context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, _ := utils.InitMongoClient()

	//Get MenuItem Collection reference
	Pricecollection := utils.GetCollection(client, "apiDB", "menuitems")

	//Query and decode result

	var price struct {
		Price float64 `json:"price" bson:"price"`
	}

	err := Pricecollection.FindOne(ctx, bson.M{"title": menuTitle}).Decode(&price)
	if err != nil {
		log.Printf("Error finding price for menu item")
	}

	return price.Price, nil

}

func (db *DB) GetCartItemsForUser(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)

	userID, err := getUserIDFromUsername(username)
	if err != nil {
		log.Printf("Failed to get UserID from Username: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	fmt.Println(userID)
	id, _ := primitive.ObjectIDFromHex(userID)

	// Query Cart collection for given userID
	cursor, err := db.CartCollection.Find(context.TODO(), bson.M{"user": id})
	if err != nil {
		log.Printf("Error querying cart items: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	var cartItems = make([]models.Cart, 0)
	for cursor.Next(context.TODO()) {
		var cartItem models.Cart
		if err := cursor.Decode(&cartItem); err != nil {
			log.Printf("Failed to decode cart item: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		cartItems = append(cartItems, cartItem)
	}
	if err := cursor.Err(); err != nil {
		log.Printf("Error while iterating over cart items: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Encode the result as JSON and write to response
	jsonBytes, err := json.Marshal(cartItems)
	if err != nil {
		log.Printf("Failed to encode cart items to JSON: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonBytes)
}

// Endpoint to delete menu items from the menu collection
func (db *DB) DeleteMenuItemsFromCart(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)

	userID, err := getUserIDFromUsername(username)
	if err != nil {
		log.Printf("Failed to get UserID from Username: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	// fmt.Println(userID)
	id, _ := primitive.ObjectIDFromHex(userID)
	filter := bson.M{"user": id}
	_, err = db.CartCollection.DeleteMany(context.TODO(), filter)
	if err != nil {
		http.Error(w, "Cannot delete database record", http.StatusBadRequest)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Menu Item deleted from Cart successfully"})
}

func (db *DB) CartEndpoint(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		db.GetCartItemsForUser(w, r)
	case http.MethodPost:
		db.PostMenuItemstoCart(w, r)
	case http.MethodDelete:
		db.DeleteMenuItemsFromCart(w, r)
	}
}

func (db *DB) PlaceNewOrderHandler(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from token or context
	username := r.Context().Value("username").(string)
	userIDstr, err := getUserIDFromUsername(username)
	if err != nil {
		http.Error(w, "Cant get UserID from Username", http.StatusBadRequest)
		return
	}
	// Convert the user ID string to primitive.ObjectID
	userID, err := primitive.ObjectIDFromHex(userIDstr)
	if err != nil {
		http.Error(w, "Cant convert UserID to primitive.ObjectID", http.StatusBadRequest)
		return
	}

	// Retrieve current cart items from the cart endpoint
	cartURL := "http://localhost:8000/api/cart/menu-items"
	req, err := http.NewRequest("GET", cartURL, nil)
	if err != nil {
		http.Error(w, "Failed to create request to retrieve cart items", http.StatusInternalServerError)
		return
	}
	req.Header.Set("token", r.Header.Get("token")) // Pass the token to the cart endpoint

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to retrieve cart items", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, "Failed to retrieve cart items", resp.StatusCode)
		return
	}

	var cartItems []models.Cart
	if resp.ContentLength == 0 {
		http.Error(w, "Empty response body", http.StatusInternalServerError)
		return
	}

	if resp.Body == nil {
		http.Error(w, "Response body is nil", http.StatusInternalServerError)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response body", http.StatusInternalServerError)
		return
	}
	
	err = json.Unmarshal(body, &cartItems)
	if err != nil {
		http.Error(w, "Failed to unmarshal cart items: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Create a new order
	order := models.Order{
		User:         userID,
		DeliveryCrew: primitive.Null{},
		Status:       false, // Assuming the order is initially not completed
		Date:         time.Now(),
	}

	// Calculate the total price of the order
	var totalPrice float64
	for _, item := range cartItems {
		totalPrice += item.Price
	}
	order.Total = totalPrice

	// Insert the order into the database
	_, err = db.OrdersCollection.InsertOne(context.Background(), order)
	if err != nil {
		http.Error(w, "Failed to create new order", http.StatusInternalServerError)
		return
	}

	// Insert cart items as order items
	for _, item := range cartItems {
		orderItem := models.OrderItem{
			Order:     order.ID,
			MenuItem:  item.MenuItem,
			Quantity:  item.Quantity,
			UnitPrice: item.UnitPrice,
			Price:     item.Price,
		}
		_, err := db.OrderItemCollection.InsertOne(context.Background(), orderItem)
		if err != nil {
			http.Error(w, "Failed to create order item", http.StatusInternalServerError)
			return
		}
	}

	// Clear the user's cart (delete all cart items)
	_, err = db.CartCollection.DeleteMany(context.Background(), bson.M{"user": userID})
	if err != nil {
		http.Error(w, "Failed to clear cart items", http.StatusInternalServerError)
		return
	}

	// Respond with success message
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Order placed successfully"))
}

//Get Orders Endpoint

func (db *DB) GetallOrders(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	userIDstr, err := getUserIDFromUsername(username)
	if err != nil {
		http.Error(w, "Cant decode userID from username", http.StatusInternalServerError)
		return
	}

	id, _ := primitive.ObjectIDFromHex(userIDstr)

	// Query Cart collection for given userID
	cursor, err := db.OrdersCollection.Find(context.TODO(), bson.M{"user": id})
	if err != nil {
		log.Printf("Error querying cart items: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	var orders []models.Order
	for cursor.Next(context.TODO()) {
		var order models.Order
		if err := cursor.Decode(&order); err != nil {
			log.Printf("Failed to decode cart item: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		orders = append(orders, order)
	}
	if err := cursor.Err(); err != nil {
		log.Printf("Error while iterating over cart items: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Encode the result as JSON and write to response
	jsonBytes, err := json.Marshal(orders)
	if err != nil {
		log.Printf("Failed to encode cart items to JSON: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonBytes)

}

func (db *DB) OrderEndpoint(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		db.GetallOrders(w, r)
	case http.MethodPost:
		db.PlaceNewOrderHandler(w, r)
	default:
		http.Error(w, "Request Method not Accepted", http.StatusBadRequest)
	}
}

type PaymentRequest struct {
	OrderID string `json:"order_id"`
	// Amount      int64  `json:"amount"`
	Currency    string `json:"currency"`
	SourceToken string `json:"source_token"`
}

type PaymentResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// func (db *DB) ProcessPaymentHandler(w http.ResponseWriter, r *http.Request) {
//     var paymentReq PaymentRequest
//     err := json.NewDecoder(r.Body).Decode(&paymentReq)
//     if err != nil {
//         http.Error(w, "Invalid request payload", http.StatusBadRequest)
//         return
//     }

//     stripe.Key = os.Getenv("************")

//     chargeParams := &stripe.ChargeParams{
//         Amount:   stripe.Int64(paymentReq.Amount),
//         Currency: stripe.String(paymentReq.Currency),
//         Source:   &stripe.SourceParams{Token: stripe.String(paymentReq.SourceToken)},
//     }
//     chargeParams.AddMetadata("order_id", paymentReq.OrderID)

//     _, err = charge.New(chargeParams)
//     if err != nil {
//         http.Error(w, "Failed to process payment", http.StatusInternalServerError)
//         return
//     }

//     paymentResp := PaymentResponse{
//         Status:  "success",
//         Message: "Payment processed successfully",
//     }
//     w.Header().Set("Content-Type", "application/json")
//     json.NewEncoder(w).Encode(paymentResp)
// }

func (db *DB) ProcessPaymentHandler1(w http.ResponseWriter, r *http.Request) {
	var paymentReq PaymentRequest
	err := json.NewDecoder(r.Body).Decode(&paymentReq)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Retrieve the order details
	orderID, err := primitive.ObjectIDFromHex(paymentReq.OrderID)
	if err != nil {
		http.Error(w, "Invalid order ID", http.StatusBadRequest)
		return
	}

	var order models.Order
	err = db.OrdersCollection.FindOne(context.TODO(), bson.M{"_id": orderID}).Decode(&order)
	if err != nil {
		http.Error(w, "Order not found", http.StatusNotFound)
		return
	}

	// Process the payment using Stripe
	stripe.Key = os.Getenv("STRIPE_SECRET_KEY")

	chargeParams := &stripe.ChargeParams{
		Amount:   stripe.Int64(int64(order.Total * 100)), // Convert to cents
		Currency: stripe.String(paymentReq.Currency),
		Source:   &stripe.SourceParams{Token: stripe.String(paymentReq.SourceToken)},
	}
	chargeParams.AddMetadata("order_id", paymentReq.OrderID)

	_, err = charge.New(chargeParams)
	if err != nil {
		http.Error(w, "Failed to process payment", http.StatusInternalServerError)
		return
	}

	// Update the order status to paid
	_, err = db.OrdersCollection.UpdateOne(context.TODO(), bson.M{"_id": orderID}, bson.M{"$set": bson.M{"status": true}})
	if err != nil {
		http.Error(w, "Failed to update order status", http.StatusInternalServerError)
		return
	}

	paymentResp := PaymentResponse{
		Status:  "success",
		Message: "Payment processed successfully",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(paymentResp)
}
