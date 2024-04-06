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
	categoryCollection := utils.GetCollection(client, "apiDB", "Category")
	cartcollection := utils.GetCollection(client, "apiDB", "Cart")

	// Create an instance of your DB
	db := &handlers.DB{
		Collection:         collection,
		TokenCollection:    tokensCollection,
		MenuItemCollection: menuitemscollection,
		UserGroup:          UserGroupcollection,
		CategoryCollection: categoryCollection,
		CartCollection:     cartcollection,
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
	currentUserRouter.HandleFunc("/cart/menu-items", db.PostMenuItemstoCart).Methods("POST")

	//Define routes that require jwttoken validation middleware
	userRouter := mainRouter.PathPrefix("/api").Subrouter()
	userRouter.Use(middleware.JWTTokenValidationMiddleware)
	userRouter.HandleFunc("/assign-group", db.AssignGroupHandler).Methods("POST")
	userRouter.HandleFunc("/assign-category", db.PostItemCategory).Methods("POST")
	userRouter.HandleFunc("/categories", db.GetAllItemCategories).Methods("GET")
	userRouter.HandleFunc("/groups/manager/users", db.ManageMangersHandler).Methods("GET", "POST")
	userRouter.HandleFunc("/groups/delivery-crew/users", db.ManageDeliveryHanlder).Methods("GET", "POST")
	userRouter.HandleFunc("/groups/manager/users/{id:[a-zA-Z0-9]*}", db.DeleteManagerHandler).Methods("DELETE")
	userRouter.HandleFunc("/groups/delivery-crew/users/{id:[a-zA-Z0-9]*}", db.DeleteDeliveryHandler).Methods("DELETE")
	userRouter.Handle("/menu-items", middleware.Authorize(http.HandlerFunc(db.ManageMenuHanlder), "Manager", "Delivery Crew", "Customer")).Methods("GET", "POST")
	userRouter.Handle("/menu-items/{id:[a-zA-Z0-9]*}", middleware.Authorize(http.HandlerFunc(db.ManageSingleItemHandler), "Manager", "Delivery Crew", "Customer")).Methods("GET", "PUT", "PATCH", "DELETE")
	userRouter.HandleFunc("/cart/menu-items", db.PostMenuItemstoCart).Methods("POST")
	//userRouter.HandleFunc("/menu-items/{id:[a-zA-Z0-9]*}", db.DeleteSingleMenuItem).Methods("DELETE")
	//userRouter.HandleFunc("/menu-items/{id:[a-zA-Z0-9]*}", db.GetSingleleMenuItem).Methods("GET")

	// Serve the main router
	http.Handle("/", mainRouter)

	srv := &http.Server{
		Handler:      mainRouter,
		Addr:         "127.0.0.1:8000",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}
