package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

//User represents a user in the system

type User struct {
	ID       interface{} `json:"id" bson:"_id,omitempty"`
	Name     string      `json:"name" bson:"name"`
	Email    string      `json:"email" bson:"email"`
	Password string      `json:"password" bson:"password"`
}

type SingleUser struct {
	Name  string `json:"name" bson:"name"`
	Email string `json:"email" bson:"email"`
}

type Category struct {
	ID    primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Slug  string             `json:"slug" bson:"slug"`
	Title string             `json:"title" bson:"title"`
}

type MenuItem struct {
	ID       primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Title    string             `json:"title" bson:"title"`
	Price    float64            `json:"price" bson:"price"`
	Featured bool               `json:"featured" bson:"featured"`
	Category primitive.ObjectID `json:"category" bson:"category"`
}

type Cart struct {
	ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	User      primitive.ObjectID `json:"user" bson:"user"`
	MenuItem  primitive.ObjectID `json:"menuitem" bson:"menuitem"`
	Quantity  int16              `json:"quantity" bson:"quantity"`
	UnitPrice float64            `json:"unit_price" bson:"unit_price"`
	Price     float64            `json:"price" bson:"price"`
}

type Order struct {
	ID           primitive.ObjectID  `json:"id" bson:"_id,omitempty"`
	User         primitive.ObjectID  `json:"user" bson:"user"`
	DeliveryCrew *primitive.ObjectID `json:"delivery_crew" bson:"delivery_crew,omitempty"`
	Status       bool                `json:"status" bson:"status"`
	Total        float64             `json:"total" bson:"total"`
	Date         time.Time           `json:"date" bson:"date"`
}

type OrderItem struct {
	ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Order     primitive.ObjectID `json:"order" bson:"order"`
	MenuItem  primitive.ObjectID `json:"menuitem" bson:"menuitem"`
	Quantity  int16              `json:"quantity" bson:"quantity"`
	UnitPrice float64            `json:"unit_price" bson:"unit_price"`
	Price     float64            `json:"price" bson:"price"`
}
