package main

import (
	"context"
	"go_trial/gorest/handlers"
	"go_trial/gorest/utils"
	"log"
	"net/http"
	"time"

	"go_trial/gorest/middleware"

	"github.com/gorilla/mux"
)

func main() {
	// Initialize MongoDB client
	client, err := utils.InitMongoClient()
	if err != nil {
		panic(err)
	}
	defer client.Disconnect(context.TODO())

	// Get database collection
	collection := utils.GetCollection(client, "apiDB", "logistics")
	tokensCollection := utils.GetCollection(client, "apiDB", "tokens")
	menuitemscollection := utils.GetCollection(client, "apiDB", "menuitems")
	UserGroupcollection := utils.GetCollection(client, "apiDB", "UserGroup")

	// Create an instance of your DB
	db := &handlers.DB{
		Collection:         collection,
		TokenCollection:    tokensCollection,
		MenuItemCollection: menuitemscollection,
		UserGroup:          UserGroupcollection,
	}
	mainRouter := mux.NewRouter()

	//Define routes that require RequestBody validation
	validationRouter := mainRouter.PathPrefix("/api").Subrouter()
	validationRouter.Use(middleware.ValidateRequestBody)
	validationRouter.HandleFunc("/users", db.CreateUserhandler).Methods("POST")

	// Define routes that don't use any middleware
	noMiddlewareRouter := mainRouter.PathPrefix("/token").Subrouter()
	noMiddlewareRouter.HandleFunc("/login/", db.LoginTokenHandler).Methods("POST")

	// Define routes that require current user middleware
	currentUserRouter := mainRouter.PathPrefix("/api").Subrouter()
	currentUserRouter.Use(middleware.SetCurrentUserMiddleware)
	currentUserRouter.HandleFunc("/users/me/", db.GetCurrentUserHandler).Methods("GET")

	//Define routes that require jwttoken validation middleware
	userRouter := mainRouter.PathPrefix("/api").Subrouter()
	userRouter.Use(middleware.JWTTokenValidationMiddleware)
	userRouter.HandleFunc("/assign-group", db.AssignGroupHandler).Methods("POST")
	userRouter.HandleFunc("/menu-items", db.PostMenuItems).Methods("POST", "PUT", "PATCH", "DELETE")
	// Serve the main router
	http.Handle("/", mainRouter)

	//Attach middleware to handle request validation
	// Define routes
	//r.Use(middleware.ValidateRequestBody)
	//r.HandleFunc("/api/users", db.CreateUserhandler).Methods("POST")

	//Not using middleware
	//r.HandleFunc("/token/login/", db.LoginTokenHandler).Methods("POST")

	//r.Use(middleware.SetCurrentUserMiddleware)
	//r.HandleFunc("/api/users/me/", db.GetCurrentUserHandler).Methods("GET")

	srv := &http.Server{
		Handler:      mainRouter,
		Addr:         "127.0.0.1:8000",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}
