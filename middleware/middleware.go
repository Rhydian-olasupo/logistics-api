package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"go_trial/gorest/utils"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// ValidateRequestBody is a middleware function to validate request Body
func ValidateRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ensure that the request method is POST
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Ensure that the Content-Type header is application/json
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			http.Error(w, "Content-Type header must be application/json", http.StatusUnsupportedMediaType)
			return
		}

		// Read the request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusInternalServerError)
			return
		}

		// Check if the request body is empty
		if len(body) == 0 {
			http.Error(w, "Request body is empty", http.StatusBadRequest)
			return
		}

		// Define a struct representing the expected fields
		type RequestData struct {
			Name     string `json:"name"`
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		// Unmarshal the request body into the struct
		var requestData RequestData
		if err := json.Unmarshal(body, &requestData); err != nil {
			http.Error(w, "Error decoding JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Check if required fields are empty
		if requestData.Name == "" || requestData.Email == "" || requestData.Password == "" {
			http.Error(w, "Name, email, and password are required fields", http.StatusBadRequest)
			return
		}

		// Create a new request with the modified body
		r.Body = io.NopCloser(bytes.NewReader(body))

		// Call the next handler in the chain
		next.ServeHTTP(w, r)
	})
}

var secretKey = []byte(os.Getenv("session_secret"))

// Define a custom type for context key
//type contextKey string

// Define a constant for the context key
/*var (
	currentUserKey contextKey = "currentUser"
)*/

// SetCurrentUserMiddleware is a middleware function that sets the current user in the request context based on JWT token.

//JWTTokenValidationMiddleware validates the token provided by the user and authorizes the usr

func JWTTokenValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("token")
		// Parse and validate the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Ensure the token signing method is what you expect
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			// Replace 'secretKey' with your actual secret key ([]byte)
			return secretKey, nil
		})
		if err != nil || !token.Valid {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Access Denied; Please check the access token"))
			return
		}
		// Extract claims from the token
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Invalid token claims"))
			return
		}
		// Extract the "name" claim (as a string)
		name, ok := claims["username"].(string)
		if !ok {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Missing or invalid 'name' field in claims"))
			return
		}

		userToken, err := findTokenByUsername(name)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error finding user token: " + err.Error()))
			return
		}

		if userToken != tokenString {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Access forbidden; Incorrect token"))
			return

		}
		next.ServeHTTP(w, r)

	})
}

// Function to query MongoDb collection to find user's token by username
func findTokenByUsername(username string) (string, error) {
	// Establish MongoDB connection with context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // Adjust timeout as needed
	defer cancel()

	client, err := utils.InitMongoClient()
	if err != nil {
		return "", fmt.Errorf("error initializing MongoDB client: %w", err)
	}
	defer client.Disconnect(ctx)

	// Get collection reference
	tokensCollection := utils.GetCollection(client, "apiDB", "tokens")

	// Query and decode result
	var result struct {
		Token string `json:"tokens" bson:"tokens"`
	}
	err = tokensCollection.FindOne(ctx, bson.M{"username": username}).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return "", fmt.Errorf("token not found for username: %s", username)
		}
		return "", fmt.Errorf("error finding token: %w", err) // Wrap errors for better handling
	}

	fmt.Println(result.Token)

	return result.Token, nil
}

// Function to extract username from JWT token in the request
func getUsernameFromToken(r *http.Request) (string, error) {
	// Extract the token from the request header
	tokenString := r.Header.Get("token")

	// Parse and validate the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the token signing method is what you expect
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Replace 'secretKey' with your actual secret key ([]byte)
		return secretKey, nil
	})

	if err != nil || !token.Valid {
		return "", fmt.Errorf("invalid or expired token: %v", err)
	}

	// Extract claims from the token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid token claims")
	}

	// Extract the "username" claim (as a string)
	username, ok := claims["username"].(string)
	if !ok {
		return "", errors.New("missing or invalid 'username' field in claims")
	}

	return username, nil
}

// Middleware function to set the current user in the request context
func SetCurrentUserMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add logging statement to indicate middleware execution
		fmt.Println("SetCurrentUserMiddleware: Middleware executed")

		// Retrieve username from token in the request
		username, err := getUsernameFromToken(r)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Access Denied; Please check the access token"))
			return
		}

		// Set the username value in the request context
		ctx := context.WithValue(r.Context(), "username", username)

		// Call the next handler in the chain with the modified context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
