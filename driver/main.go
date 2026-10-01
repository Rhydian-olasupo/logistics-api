package main

import (
	"context"
	"errors"
	"go_trial/gorest/handlers"
	"go_trial/gorest/telem"
	"go_trial/gorest/utils"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go_trial/gorest/middleware"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"

	"go_trial/gorest/middleware/logkafka"
)

func main() {

	// Load variables from .env in the working directory. Variables already set in the
	// shell take precedence, so a missing file is fine (e.g. in production).
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file loaded; using environment variables only")
	}

	handlers.Init()
	ctx := context.Background()

	// FIX: tokens used to be signed with an empty key when the secret env var was unset.
	if len(utils.JWTSecret()) == 0 {
		log.Fatal("JWT_SECRET (or session_secret) must be set")
	}

	// Initialize metrics
	metricsShutdown, err := telem.InitMetrics("my-service")
	if err != nil {
		log.Fatalf("Failed to initialize metrics: %v", err)
	}
	defer metricsShutdown(ctx)

	// Initialize tracing
	tracingShutdown, err := telem.InitTracing("my-service")
	if err != nil {
		log.Fatalf("Failed to initialize tracing: %v", err)
	}
	defer tracingShutdown(ctx)

	// Initialize MongoDB client
	client, err := utils.InitMongoClient()
	if err != nil {
		panic(err)
	}
	defer client.Disconnect(context.TODO())

	// Get database collection
	collection := utils.GetCollection(client, "apiDB", "logistics")
	// tokensCollection := utils.GetCollection(client, "apiDB", "tokens")
	menuitemscollection := utils.GetCollection(client, "apiDB", "menuitems")
	UserGroupcollection := utils.GetCollection(client, "apiDB", "UserGroup")
	categoryCollection := utils.GetCollection(client, "apiDB", "Category")
	cartcollection := utils.GetCollection(client, "apiDB", "Cart")
	orderscollection := utils.GetCollection(client, "apiDB", "Orders")
	orderitemcollection := utils.GetCollection(client, "apiDB", "OrderItem")
	refreshtokencollection := utils.GetCollection(client, "apiDB", "RefreshTokens")
	blacklistcollection := utils.GetCollection(client, "apiDB", "Blacklist")
	auditcollection := utils.GetCollection(client, "apiDB", "Audit")

	// Create an instance of the DB
	db := &handlers.DB{
		Collection: collection,
		// TokenCollection:          tokensCollection,
		MenuItemCollection:       menuitemscollection,
		UserGroup:                UserGroupcollection,
		CategoryCollection:       categoryCollection,
		CartCollection:           cartcollection,
		OrdersCollection:         orderscollection,
		OrderItemCollection:      orderitemcollection,
		RefreshTokenCollection:   refreshtokencollection,
		TokenBlacklistCollection: blacklistcollection,
		AuditLogCollection:       auditcollection,
	}
	mainRouter := mux.NewRouter()
	//Define routes that require RequestBody validation
	validationRouter := mainRouter.PathPrefix("/api").Subrouter()

	validationRouter.Use(middleware.ValidateRequestBody)
	validationRouter.HandleFunc("/users", db.CreateUserHandler).Methods("POST")

	// Define routes that don't use any middleware
	noMiddlewareRouter := mainRouter.PathPrefix("/token").Subrouter()
	noMiddlewareRouter.HandleFunc("/login/", db.LoginTokenHandler).Methods("POST")
	noMiddlewareRouter.HandleFunc("/refresh_token", db.RefreshTokenHandler).Methods("POST")

	// Define routes that require current user middleware
	currentUserRouter := mainRouter.PathPrefix("/api").Subrouter()
	currentUserRouter.Use(middleware.SetCurrentUserMiddleware)
	currentUserRouter.HandleFunc("/user/me/", db.GetCurrentUserHandler).Methods("GET")
	currentUserRouter.HandleFunc("/cart/menu-items", db.CartEndpoint).Methods("GET", "POST", "DELETE")
	currentUserRouter.HandleFunc("/orders", db.OrderEndpoint).Methods("GET", "POST")
	currentUserRouter.HandleFunc("/logout", db.LogoutUserHandler).Methods("POST")

	//Define routes that require jwttoken validation middleware
	userRouter := mainRouter.PathPrefix("/api").Subrouter()
	userRouter.Use(middleware.JWTTokenValidationMiddleware)
	userRouter.HandleFunc("/assign-group", db.AssignGroupHandler).Methods("POST")
	userRouter.HandleFunc("/assign-category", db.PostItemCategory).Methods("POST")
	userRouter.HandleFunc("/categories", db.GetAllItemCategories).Methods("GET")
	// FIX: the /groups routes never ran Authorize, so the handlers' role lookup found
	// nothing and panicked. Wrapping them puts the role in the context; the handlers
	// still restrict POST/DELETE to Managers themselves.
	allRoles := []string{"Manager", "Delivery Crew", "Customer"}
	userRouter.Handle("/groups/manager/users", middleware.Authorize(UserGroupcollection, http.HandlerFunc(db.ManageMangersHandler), allRoles...)).Methods("GET", "POST")
	userRouter.Handle("/groups/delivery-crew/users", middleware.Authorize(UserGroupcollection, http.HandlerFunc(db.ManageDeliveryHanlder), allRoles...)).Methods("GET", "POST")
	userRouter.Handle("/groups/manager/users/{id:[a-zA-Z0-9]*}", middleware.Authorize(UserGroupcollection, http.HandlerFunc(db.DeleteManagerHandler), "Manager")).Methods("DELETE")
	userRouter.Handle("/groups/delivery-crew/users/{id:[a-zA-Z0-9]*}", middleware.Authorize(UserGroupcollection, http.HandlerFunc(db.DeleteDeliveryHandler), "Manager")).Methods("DELETE")
	// FIX: Authorize now receives the UserGroup collection instead of opening its own client per request.
	userRouter.Handle("/menu-items", middleware.Authorize(UserGroupcollection, http.HandlerFunc(db.ManageMenuHanlder), allRoles...)).Methods("GET", "POST")
	userRouter.Handle("/menu-items/{id:[a-zA-Z0-9]*}", middleware.Authorize(UserGroupcollection, http.HandlerFunc(db.ManageSingleItemHandler), allRoles...)).Methods("GET", "PUT", "PATCH", "DELETE")
	// FIX: removed a duplicate POST /api/cart/menu-items registration. currentUserRouter
	// above already matches it first, so this one was dead code (and it skipped the
	// middleware that sets the username, so it would have failed if it ever ran).
	//userRouter.HandleFunc("/logout", db.LogoutUserHandler).Methods("POST")
	//userRouter.HandleFunc("/menu-items/{id:[a-zA-Z0-9]*}", db.DeleteSingleMenuItem).Methods("DELETE")
	//userRouter.HandleFunc("/menu-items/{id:[a-zA-Z0-9]*}", db.GetSingleleMenuItem).Methods("GET")

	// FIX: Kafka brokers/topic used to be hard-coded; they now come from the environment
	// (KAFKA_BROKERS, KAFKA_LOG_TOPIC) with the old values as defaults.
	brokers := utils.KafkaBrokers()
	logTopic := utils.Getenv("KAFKA_LOG_TOPIC", "logs")

	// Initialize Kafka writer for logging
	logkafka.InitKafkaWriter(brokers, logTopic)
	defer logkafka.CloseKafkaWriter()

	// FIX: cancelled on Ctrl+C / SIGTERM so the server and the Kafka→ES pusher can stop cleanly.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start Kafka to Elasticsearch batch pusher in a goroutine
	pusherDone := make(chan struct{})
	go func() {
		defer close(pusherDone)
		utils.InitKafkaES(ctx, brokers, logTopic)
	}()

	// Wrap the main router with the logging middleware
	// FIX: EnableCors existed but was never applied, so browser clients (e.g. the Flutter web
	// app in backend_test_app) were blocked. It wraps the router so OPTIONS preflights are
	// answered before mux rejects them for not matching a route's methods.
	loggedRouter := logkafka.LoggingMiddleware(middleware.EnableCors(mainRouter))

	addr := utils.Getenv("API_ADDR", "127.0.0.1:8000")
	srv := &http.Server{
		Handler:      loggedRouter,
		Addr:         addr,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	go func() {
		log.Printf("API listening on http://%s", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	// FIX: this used to be log.Fatal(srv.ListenAndServe()). log.Fatal calls os.Exit, which
	// skips every deferred call above, so buffered Kafka logs, pending trace spans and the
	// Mongo connection were never flushed/closed. Now we wait for a signal, drain in-flight
	// requests, let the pusher flush its last batch, then return so the defers run.
	<-ctx.Done()
	log.Println("Shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP shutdown error: %v", err)
	}
	<-pusherDone
}
