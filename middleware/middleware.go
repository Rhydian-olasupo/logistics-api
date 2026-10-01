package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go_trial/gorest/utils"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func EnableCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, PATCH, DELETE")
		// FIX: the API reads the JWT from a custom "token" header, which browsers only send if allowed here
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, token")
		if r.Method == "OPTIONS" {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ValidateRequestBody is a middleware function to validate request Body
func ValidateRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ensure that the request method is POST
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Ensure that the Content-Type header is application/json or starts with it
		contentType := r.Header.Get("Content-Type")
		if !strings.HasPrefix(contentType, "application/json") {
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
		r.Body = io.NopCloser(bytes.NewBuffer(body))

		// Call the next handler in the chain
		next.ServeHTTP(w, r)
	})
}

// FIX: context values used to be stored under plain strings ("username", "userrole")
// and read back under different spellings ("userRole"), so lookups returned nil and
// the handlers' .(string) assertions panicked. A private key type means nothing outside
// this package can collide with these keys, and the compiler catches typos.
type contextKey string

const (
	UsernameKey contextKey = "username"
	UserRoleKey contextKey = "userrole"
)

// UsernameFrom returns the username set by SetCurrentUserMiddleware or Authorize.
func UsernameFrom(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(UsernameKey).(string)
	return username, ok
}

// UserRoleFrom returns the role set by Authorize.
func UserRoleFrom(ctx context.Context) (string, bool) {
	role, ok := ctx.Value(UserRoleKey).(string)
	return role, ok
}

// // Define a custom type for context key
// type contextKey string

// // //Define a constant for the context key
// const (
// 	USERNAME contextKey = "USERNAME"
// 	USERROLE contextKey = "USERROLE"
// )

// type user struct {
// 	Username string `json:"username" bson:"username"`
// }

// // AuthMiddleware validates the JWT token and sets the user in the context
// func (db *DB) AuthMiddleware(next http.Handler) http.Handler {
//     return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//         // Extract the token from the Authorization header
//         tokenString := r.Header.Get("token")
//         if tokenString == "" {
//             http.Error(w, "Authorization header and token missing", http.StatusUnauthorized)
//             return
//         }

//         // parts := strings.SplitN(authHeader, " ", 2)
//         // if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
//         //     http.Error(w, "Invalid Authorization header format. Expected 'Bearer <token>'", http.StatusUnauthorized)
//         //     return
//         // }
//         secretKey := []byte(os.Getenv("session_secret"))

//         // Parse and validate the token
//         token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
//             if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
//                 return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
//             }
//             return secretKey, nil
//         })

//         if err != nil || !token.Valid {
//             http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
//             return
//         }

//         // Extract claims
//         claims, ok := token.Claims.(jwt.MapClaims)
//         if !ok {
//             http.Error(w, "Invalid token claims", http.StatusUnauthorized)
//             return
//         }

//         // Extract the "username" claim
//         username, ok := claims["username"].(string)
//         if !ok {
//             http.Error(w, "Invalid token payload", http.StatusUnauthorized)
//             return
//         }

//         // // Optionally, you can retrieve additional user information from the database
//         // var user User
//         // ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//         // defer cancel()

//         // err = db.Collection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
//         // if err != nil {
//         //     if err == mongo.ErrNoDocuments {
//         //         http.Error(w, "User not found", http.StatusUnauthorized)
//         //         return
//         //     }
//         //     http.Error(w, "Internal server error", http.StatusInternalServerError)
//         //     return
//         // }

//         // Attach user to the request context
//         ctx = context.WithValue(r.Context(), currentUserKey, user)
//         next.ServeHTTP(w, r.WithContext(ctx))
//     })
// }

// SetCurrentUserMiddleware is a middleware function that sets the current user in the request context based on JWT token.
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
		// FIX: use the typed key instead of the plain string "username"
		ctx := context.WithValue(r.Context(), UsernameKey, username)
		// Call the next handler in the chain with the modified context
		next.ServeHTTP(w, r.WithContext(ctx))

	})
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
		return utils.JWTSecret(), nil
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
			return utils.JWTSecret(), nil
		})
		if err != nil || !token.Valid {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Access Denied; Please check the access token"))
			return
		}
		next.ServeHTTP(w, r)

	})
}

// Middleware function to enforce role-base authorization
//
// FIX: Authorize now takes the UserGroup collection from main instead of opening a
// brand-new MongoDB client (and connection pool) on every request in getUserRoleFromDB.
func Authorize(userGroups *mongo.Collection, next http.Handler, requiredRoles ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// FIX: the token error used to be ignored, so a bad token fell through with an
		// empty username and was treated as a "Customer". Reject it up front instead.
		username, err := getUsernameFromToken(r)
		if err != nil {
			http.Error(w, "Access Denied; Please check the access token", http.StatusForbidden)
			return
		}

		//Retrieve authenticated user's role from UserGroup collection
		userRole, err := getUserRoleFromDB(r.Context(), userGroups, username)
		if err != nil {
			http.Error(w, "Cant retrieve user role from database record", http.StatusInternalServerError)
			return
		}

		//check if the authenticated user role matches any of the the required roles
		authorized := false
		for _, requiredRole := range requiredRoles {
			if userRole == requiredRole {
				authorized = true
				break
			}

		}
		//If the authenticated user's role is not authorized, return unauthorized error

		if !authorized {
			http.Error(w, "Unathorized", http.StatusUnauthorized)
			// FIX: without this return the request carried on to the handler anyway
			return
		}

		// FIX: store role and username under the typed keys so handlers can read them back
		ctx := context.WithValue(r.Context(), UserRoleKey, userRole)
		ctx = context.WithValue(ctx, UsernameKey, username)

		// Call the next handler in the chain with the modified context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Function to get userRole from the UserGroup collection
func getUserRoleFromDB(ctx context.Context, userGroups *mongo.Collection, username string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second) // Adjust timeout as needed
	defer cancel()

	// Query and decode result
	var userGroup struct {
		Group string `json:"group" bson:"group"`
	}

	err := userGroups.FindOne(ctx, bson.M{"name": username}).Decode(&userGroup)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			// User not found in UserGroup collection, return default role for customers
			return "Customer", nil
		}
		return "", fmt.Errorf("error retrieving user group: %w", err)
	}

	return userGroup.Group, nil
}
