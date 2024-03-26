package middleware

import (
	"encoding/json"
	"fmt"
	"go_trial/gorest/models"
	"net/http"
)

//ValidateRequestBody is a middleware function to validate request Body

func ValidateRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for empty request body
		if r.Body == nil || r.ContentLength == 0 {
			http.Error(w, "Request body is empty", http.StatusBadRequest)
			return
		}

		var newUser models.User
		if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
			// Handle other decoding errors here
			fmt.Println("Error decoding JSON in middleware:", err)
			http.Error(w, "Invalid Request Body", http.StatusBadRequest)
			return
		}

		// Existing validation logic for required fields
		if newUser.Name == "" || newUser.Email == "" || newUser.Password == "" {
			http.Error(w, "Name, email and password are required", http.StatusBadRequest)
			return
		}

		// Proceed to the next handler if validation passes
		next.ServeHTTP(w, r)
	})
}
