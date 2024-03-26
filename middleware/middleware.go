package middleware

import (
	"encoding/json"
	"go_trial/gorest/models"
	"net/http"
)

//ValidateRequestBody is a middleware function to validate request Body

func ValidateRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var newUser models.User
		if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
			http.Error(w, "Invalid request Body", http.StatusBadRequest)
			return
		}

		//check if the user require field are presents.

		if newUser.Name == "" || newUser.Email == "" || newUser.Password == "" {
			http.Error(w, "Name, email and password are required", http.StatusBadRequest)
			return
		}

		//Proceeds to the next handler if validation passes
		next.ServeHTTP(w, r)
	})

}
