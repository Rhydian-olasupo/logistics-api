package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"go_trial/gorest/models"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type DB struct {
	Collection         *mongo.Collection
	TokenCollection    *mongo.Collection
	MenuItemCollection *mongo.Collection
	UserGroup          *mongo.Collection
	CategoryCollection *mongo.Collection
}

var secretKey = []byte(os.Getenv("session_secret"))

/*var (
	mongoClient *mongo.Client
	dbName      = "apiDB"
	collection  = "logistics"
)*/

type Response struct {
	Token string `json:"token" bson:"token"`
}

//CreateUserhandler handles requests to create new user

func (db *DB) CreateUserhandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Request Body:", r.Body)
	// Declare a variable to hold the new user
	var newUser models.User

	// Read the request body
	postBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Decode the JSON request body into newUser struct
	if err := json.Unmarshal(postBody, &newUser); err != nil {
		http.Error(w, "Error decoding JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Insert the new user into the database
	result, err := db.Collection.InsertOne(context.TODO(), newUser)
	if err != nil {
		http.Error(w, "Failed to create user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Prepare the response
	response := map[string]interface{}{
		"message":     "User created successfully",
		"inserted_id": result.InsertedID,
	}

	// Encode the response as JSON and send it
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Error encoding response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func (db *DB) LoginTokenHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Please poass the data in URL encoded form", http.StatusBadRequest)
		return
	}

	username := r.PostForm.Get("name")
	password := r.PostForm.Get("password")

	// Log what the endpoint is receiving
	fmt.Printf("Received request for username: %s\n", username)
	fmt.Printf("Received request for password: %s\n", password)

	// MongoDB client and context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// MongoDB collection instance
	//collection := mongoClient.Database(dbName).Collection(collection)

	// Find the user by username
	var user struct {
		Password string `json:"password" bson:"password"`
	}
	err = db.Collection.FindOne(ctx, bson.M{"name": username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if password != user.Password {
		http.Error(w, "Invalid Password", http.StatusUnauthorized)
		return
	}

	// Password is correct, generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"iat":      time.Now().Unix(),
	})
	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	//Insert the username and JWT token into the tokensCollection

	_, err = db.TokenCollection.InsertOne(ctx, bson.M{"username": username, "tokens": tokenString})
	if err != nil {
		http.Error(w, "Failed to oinsert token into the database", http.StatusInternalServerError)
		return
	}

	// Token generated successfully, send it in the response
	response := Response{Token: tokenString}
	respJSON, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respJSON)
}

func (db *DB) GetCurrentUserHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve username from context
	username := r.Context().Value("username").(string)
	fmt.Println(username)

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
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
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
		log.Printf("Failed to assign group to user: %v", err)
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
	var DeliveryCrews []struct {
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
			http.Error(w, "Fialed to decode delivery crew", http.StatusInternalServerError)
			return
		}

		DeliveryCrews = append(DeliveryCrews, delivery_crew)
	}

	if err := cursor.Err(); err != nil {
		http.Error(w, "Erroe while iterating over Delivery Crews", http.StatusInternalServerError)
		return
	}

	//Encode the resutl as JSON and write to response
	jsonBytes, err := json.Marshal(DeliveryCrews)
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
	userRole := r.Context().Value("userRole").(string)
	fmt.Println(userRole)
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

func (db *DB) assignUsertoDeliveryCrewHandler(w http.ResponseWriter, r *http.Request) {
	userRole := r.Context().Value("userRole").(string)
	fmt.Println(userRole)
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
func (db *DB) DeleteManagerHandler(w http.ResponseWriter, r *http.Request) {
	userRole := r.Context().Value("userRole").(string)
	fmt.Println(userRole)
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
			json.NewEncoder(w).Encode(map[string]string{"message": "User deleted from manager group successfully"})
		}
	default:
		http.Error(w, "Unauthorized", http.StatusUnauthorized)

	}

}

func (db *DB) DeleteDeliveryHandler(w http.ResponseWriter, r *http.Request) {
	userRole := r.Context().Value("userRole").(string)
	fmt.Println(userRole)
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

	// Find all documents where group is "Manager"
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
	fmt.Println(userRole)
	switch userRole {
	case "Manager":
		var menuitem models.MenuItem
		postBody, _ := io.ReadAll(r.Body)
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

	//Calculate pagination paramters
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
				{Key: "from", Value: "Category"},       // Name of the category collection
				{Key: "localField", Value: "category"}, // Field in the local collection to match
				{Key: "foreignField", Value: "_id"},    // Field in the foreign collection to match
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
