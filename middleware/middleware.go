package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

//ValidateRequestBody is a middleware function to validate request Body

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
func SetCurrentUserMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add logging statement to indicate middleware execution
		fmt.Println("SetCurrentUserMiddleware: Middleware executed")

		// Extract the token from the request header
		tokenString := r.Header.Get("token")

		// Add logging statement to print the token
		fmt.Println("SetCurrentUserMiddleware: Token:", tokenString)

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

		// Set the "name" value in the request context
		ctx := context.WithValue(r.Context(), "username", name)

		// Call the next handler in the chain with the modified context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

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
	})
}
