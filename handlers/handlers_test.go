package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"golang.org/x/crypto/bcrypt"

	"go_trial/gorest/models"
)

var db *DB

func TestMain(m *testing.M) {
	// Setup MongoDB client and collection
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		panic(err)
	}
	defer client.Disconnect(context.TODO())

	// Ping the database to ensure connection is established
	if err := client.Ping(context.TODO(), readpref.Primary()); err != nil {
		panic(err)
	}

	// Initialize the DB struct
	db = &DB{
		Collection:               client.Database("testdb").Collection("users"),
		TokenCollection:          client.Database("testdb").Collection("tokens"),
		MenuItemCollection:       client.Database("testdb").Collection("menuitems"),
		UserGroup:                client.Database("testdb").Collection("usergroups"),
		CategoryCollection:       client.Database("testdb").Collection("categories"),
		CartCollection:           client.Database("testdb").Collection("cart"),
		OrderItemCollection:      client.Database("testdb").Collection("orderitems"),
		OrdersCollection:         client.Database("testdb").Collection("orders"),
		RefreshTokenCollection:   client.Database("testdb").Collection("refreshtokens"),
		TokenBlacklistCollection: client.Database("testdb").Collection("tokenblacklist"),
		AuditLogCollection:       client.Database("testdb").Collection("auditlog"),
	}

	// Clear the collections before running the tests
	db.Collection.DeleteMany(context.TODO(), bson.M{})
	db.TokenCollection.DeleteMany(context.TODO(), bson.M{})
	db.MenuItemCollection.DeleteMany(context.TODO(), bson.M{})
	db.UserGroup.DeleteMany(context.TODO(), bson.M{})
	db.CategoryCollection.DeleteMany(context.TODO(), bson.M{})
	db.CartCollection.DeleteMany(context.TODO(), bson.M{})
	db.OrderItemCollection.DeleteMany(context.TODO(), bson.M{})
	db.OrdersCollection.DeleteMany(context.TODO(), bson.M{})
	db.RefreshTokenCollection.DeleteMany(context.TODO(), bson.M{})
	db.TokenBlacklistCollection.DeleteMany(context.TODO(), bson.M{})
	db.AuditLogCollection.DeleteMany(context.TODO(), bson.M{})

	// Run the tests
	code := m.Run()
	os.Exit(code)
}

func TestCreateUserHandler(t *testing.T) {
	// Create a new HTTP request
	user := models.User{Name: "testuser", Email: "testuser@rhyda.com", Password: "password123"}
	body, _ := json.Marshal(user)
	req, err := http.NewRequest("POST", "api/users", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Create a ResponseRecorder to record the response
	rr := httptest.NewRecorder()

	// Call the handler
	handler := http.HandlerFunc(db.CreateUserHandler)
	handler.ServeHTTP(rr, req)

	// Check the status code
	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusCreated)
	}

	// Check the response body
	var response map[string]interface{}
	err = json.NewDecoder(rr.Body).Decode(&response)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["message"] != "User created successfully" {
		t.Errorf("handler returned unexpected message: got %v want %v", response["message"], "User created successfully")
	}
}

func TestLoginTokenHandler(t *testing.T) {
	// Add a test user to the database to simulate an existing user and create an access token
	// Insert a test user
	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	user := UserFlat{Name: "testuser", PasswordHash: string(passwordHash)}
	result, err := db.Collection.InsertOne(context.TODO(), user)
	if err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}
	user.ID = result.InsertedID.(primitive.ObjectID)
	if err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}

	// Create a new HTTP request
	reqBody := `name=testuser&password=password123`
	req, err := http.NewRequest("POST", "/login", bytes.NewBufferString(reqBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Create a ResponseRecorder to record the response
	rr := httptest.NewRecorder()

	// Call the handler
	handler := http.HandlerFunc(db.LoginTokenHandler)
	handler.ServeHTTP(rr, req)

	// Check the status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check the response body
	var response Response
	err = json.NewDecoder(rr.Body).Decode(&response)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if response.AccessToken == "" || response.RefreshToken == "" {
		t.Errorf("handler returned invalid tokens: %v", response)
	}
}
func TestPlaceNewOrderHandler(t *testing.T) {
	// Add a test user to the database to simulate an existing user
	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	user := UserFlat{Name: "testuser", PasswordHash: string(passwordHash)}
	_, err := db.Collection.InsertOne(context.TODO(), user)
	if err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}

	// Add test items to the cart
	cartItem := models.Cart{
		User:       func() primitive.ObjectID { id, _ := primitive.ObjectIDFromHex(user.ID.(string)); return id }(),
		MenuItem:  "testitem",
		Quantity:  2,
		UnitPrice: 10.0,
		Price:     20.0,
	}
	_, err = db.CartCollection.InsertOne(context.TODO(), cartItem)
	if err != nil {
		t.Fatalf("Failed to insert cart item: %v", err)
	}

	// Create a new HTTP request
	req, err := http.NewRequest("POST", "/api/orders", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req = req.WithContext(context.WithValue(req.Context(), "username", "testuser"))
	req.Header.Set("token", "test_token")

	// Create a ResponseRecorder to record the response
	rr := httptest.NewRecorder()

	// Call the handler
	handler := http.HandlerFunc(db.PlaceNewOrderHandler)
	handler.ServeHTTP(rr, req)

	// Check the status code
	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusCreated)
	}

	// Check the response body
	expected := "Order placed successfully"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}

	// Verify that the order was created in the database
	var order models.Order
	err = db.OrdersCollection.FindOne(context.TODO(), bson.M{"user": user.ID}).Decode(&order)
	if err != nil {
		t.Fatalf("Failed to find created order: %v", err)
	}

	// Verify that the order items were created in the database
	var orderItems []models.OrderItem
	cursor, err := db.OrderItemCollection.Find(context.TODO(), bson.M{"order": order.ID})
	if err != nil {
		t.Fatalf("Failed to find order items: %v", err)
	}
	defer cursor.Close(context.TODO())
	for cursor.Next(context.TODO()) {
		var orderItem models.OrderItem
		if err := cursor.Decode(&orderItem); err != nil {
			t.Fatalf("Failed to decode order item: %v", err)
		}
		orderItems = append(orderItems, orderItem)
	}
	if len(orderItems) == 0 {
		t.Errorf("No order items found for the created order")
	}

	// Verify that the cart was cleared
	count, err := db.CartCollection.CountDocuments(context.TODO(), bson.M{"user": user.ID})
	if err != nil {
		t.Fatalf("Failed to count cart items: %v", err)
	}
	if count != 0 {
		t.Errorf("Cart was not cleared after placing the order")
	}
}

// func TestRefreshTokenHandler(t *testing.T) {
// 	// Insert a test refresh token
// 	refreshToken := "test_refresh_token"
// 	_, err := db.RefreshTokenCollection.InsertOne(context.TODO(), bson.M{
// 		"username":     "testuser",
// 		"refreshToken": refreshToken,
// 	})
// 	if err != nil {
// 		t.Fatalf("Failed to insert test refresh token: %v", err)
// 	}

// 	// Create a new HTTP request
// 	reqBody := `{"refresh_token":"test_refresh_token"}`
// 	req, err := http.NewRequest("POST", "/refresh-token", bytes.NewBufferString(reqBody))
// 	if err != nil {
// 		t.Fatalf("Failed to create request: %v", err)
// 	}
// 	req.Header.Set("Content-Type", "application/json")

// 	// Create a ResponseRecorder to record the response
// 	rr := httptest.NewRecorder()

// 	// Call the handler
// 	handler := http.HandlerFunc(db.RefreshTokenHandler)
// 	handler.ServeHTTP(rr, req)

// 	// Check the status code
// 	if status := rr.Code; status != http.StatusOK {
// 		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
// 	}

// 	// Check the response body
// 	var response Response
// 	err = json.NewDecoder(rr.Body).Decode(&response)
// 	if err != nil {
// 		t.Fatalf("Failed to decode response: %v", err)
// 	}
// 	if response.AccessToken == "" {
// 		t.Errorf("handler returned invalid access token: %v", response)
// 	}
// }

// func TestLogoutUserHandler(t *testing.T) {
// 	// Insert a test user and refresh token
// 	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
// 	user := UserFlat{Name: "testuser", PasswordHash: string(passwordHash)}
// 	_, err := db.Collection.InsertOne(context.TODO(), user)
// 	if err != nil {
// 		t.Fatalf("Failed to insert test user: %v", err)
// 	}
// 	_, err = db.RefreshTokenCollection.InsertOne(context.TODO(), bson.M{
// 		"username":     "testuser",
// 		"refreshToken": "test_refresh_token",
// 	})
// 	if err != nil {
// 		t.Fatalf("Failed to insert test refresh token: %v", err)
// 	}

// 	// Create a new HTTP request
// 	req, err := http.NewRequest("POST", "/logout", nil)
// 	if err != nil {
// 		t.Fatalf("Failed to create request: %v", err)
// 	}
// 	req.Header.Set("token", "test_access_token")
// 	req = req.WithContext(context.WithValue(req.Context(), "username", "testuser"))

// 	// Create a ResponseRecorder to record the response
// 	rr := httptest.NewRecorder()

// 	// Call the handler
// 	handler := http.HandlerFunc(db.LogoutUserHandler)
// 	handler.ServeHTTP(rr, req)

// 	// Check the status code
// 	if status := rr.Code; status != http.StatusOK {
// 		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
// 	}

// 	// Check the response body
// 	expected := `{"message":"User logged out successfully"}`
// 	if rr.Body.String() != expected {
// 		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
// 	}
// }

// func TestGetCurrentUserHandler(t *testing.T) {
// 	// Insert a test user
// 	user := models.SingleUser{Name: "testuser"}
// 	_, err := db.Collection.InsertOne(context.TODO(), user)
// 	if err != nil {
// 		t.Fatalf("Failed to insert test user: %v", err)
// 	}

// 	// Create a new HTTP request
// 	req, err := http.NewRequest("GET", "/current-user", nil)
// 	if err != nil {
// 		t.Fatalf("Failed to create request: %v", err)
// 	}
// 	req = req.WithContext(context.WithValue(req.Context(), "username", "testuser"))

// 	// Create a ResponseRecorder to record the response
// 	rr := httptest.NewRecorder()

// 	// Call the handler
// 	handler := http.HandlerFunc(db.GetCurrentUserHandler)
// 	handler.ServeHTTP(rr, req)

// 	// Check the status code
// 	if status := rr.Code; status != http.StatusOK {
// 		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
// 	}

// 	// Check the response body
// 	var response models.SingleUser
// 	err = json.NewDecoder(rr.Body).Decode(&response)
// 	if err != nil {
// 		t.Fatalf("Failed to decode response: %v", err)
// 	}
// 	if response.Name != "testuser" {
// 		t.Errorf("handler returned unexpected user: got %v want %v", response.Name, "testuser")
// 	}
// }
