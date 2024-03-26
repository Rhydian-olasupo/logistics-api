package models

//User represents a user in the system

type User struct {
	ID       interface{} `json:"id" bson:"_id,omitempty"`
	Name     string      `json:"name" bson:"name"`
	Email    string      `json:"phone" bson:"phone"`
	Password string      `json:"password" bson:"password"`
}
