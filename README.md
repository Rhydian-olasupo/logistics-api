# 🍋 LittleLemonAPI - GoLang Edition

![Golang](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)  
![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=for-the-badge&logo=mongodb&logoColor=white)  
![JWT](https://img.shields.io/badge/JWT-black?style=for-the-badge&logo=JSON%20web%20tokens)  
![Flutter](https://img.shields.io/badge/Flutter-02569B?style=for-the-badge&logo=flutter&logoColor=white)  

---

## 🚦 Project Status: In Active Development (May 2025)

This project is currently in active development. Major features have been implemented, including:
- User authentication and registration (JWT-based, secure password hashing)
- Role-based access control and group management
- Menu, cart, and order management endpoints
- Token refresh and logout functionality
- Telemetry, observability, and Kafka logging integration
- Docker and Docker Compose support
- Flutter mobile frontend for user creation/testing

**Upcoming improvements:**
- More comprehensive test coverage
- Enhanced error handling and validation
- API documentation (Swagger/OpenAPI)
- Production deployment guides


---

## Overview  
The **LittleLemonAPI** is a robust and scalable backend solution for managing restaurant operations. Built with GoLang, this API supports:
- User authentication and registration.
- Menu item management.
- Cart functionality for customers.
- Role-specific order management.  

This API enables the seamless development of web and mobile applications for restaurant services.

---

## ✨ Features  

- **Secure Authentication**: JWT-based access and refresh tokens.  
- **Flexible Database**: MongoDB for scalable and dynamic data storage.  
- **Custom Middleware**: Built-in authentication middleware without third-party plugins like Gin.  
- **Role-Based Access**: Specific endpoints and permissions for Manager, Customer, and Delivery Crew.  
- **Pagination and Sorting**: Enhanced performance for large datasets.  
- **Mobile App Integration**: Supports interaction via a Flutter app.

---

## 🚀 Getting Started  

### Prerequisites  
Ensure you have the following installed:  
- [GoLang](https://golang.org/) (v1.18 or later)  
- [MongoDB](https://www.mongodb.com/) (v4.4 or later)  
- [Flutter](https://flutter.dev/) (optional, for frontend).  

---

### Project Structure

```
logistics-api/
├── backend_test_app/      # Flutter mobile app (optional frontend)
├── driver/                # Go entry point
├── handlers/              # API endpoint handlers
├── middleware/            # Custom middleware (auth, etc.)
├── logkafka/              # Kafka logging integration
├── models/                # Database models and logic
├── telem/                 # Telemetry and observability
├── utils/                 # Utility functions (e.g., MongoDB helpers)
├── docker-compose.yml     # Docker orchestration
├── go.mod, go.sum         # Go dependencies
├── README.md              # Project documentation
└── ...
```

- **backend_test_app/**: Contains a Flutter app for mobile frontend testing and integration.
- **Go backend**: All Go source code for the API is in the root-level folders (driver, handlers, etc).

---

### Installation

1. Clone the repository:  
   ```bash
   git clone https://github.com/rhydian-olasupo/LittleLemonAPI.git
   cd LittleLemonAPI
   ```

2. Install dependencies:  
   ```bash
   go mod tidy
   ```

3. Set up the environment variables by creating a `.env` file:  
   ```plaintext
   DB_URI=mongodb://localhost:27017
   JWT_SECRET=your_secret_key
   ```

4. Run the server:  
   ```bash
   go run main.go
   ```

5. The API will be available at `http://localhost:8080`.

---

### Running with Docker

You can run the API and MongoDB using Docker Compose:

```bash
docker-compose up --build
```

This will start both the Go API and a MongoDB instance as defined in `docker-compose.yml`.

---

## 📖 API Documentation  

### **Authentication Endpoints**
- **POST** `/api/users`: Register a new user.
- **POST** `/token/login/`: Authenticate user and generate tokens.
- **POST** `/token/refresh_token`: Renew access token using the refresh token.
- **GET** `/api/users/me/`: Retrieve current user details.

### **Menu Management**
- **GET** `/menu-items`: List all menu items (All Roles).  
- **POST** `/menu-items`: Add a new menu item (Manager Only).  
- **GET** `/menu-items/{menuItemID}`: Fetch menu item details.  
- **PUT, PATCH** `/menu-items/{menuItemID}`: Update a menu item (Manager Only).  
- **DELETE** `/menu-items/{menuItemID}`: Delete a menu item (Manager Only).

### **Cart Management**
- **GET** `/cart/menu-items`: Retrieve cart items (Customer Only).  
- **POST** `/cart/menu-items`: Add menu items to the cart.  
- **DELETE** `/cart/menu-items`: Clear the cart for the current user.

### **Order Management**
- **GET** `/orders`: View all orders (Role-specific access).  
- **POST** `/orders`: Place a new order using cart items (Customer Only).  
- **GET** `/orders/{orderID}`: View details of a specific order.  
- **PUT, PATCH** `/orders/{orderID}`: Assign delivery crew or update status (Manager Only).  
- **PATCH** `/orders/{orderID}`: Update delivery status (Delivery Crew Only).  

### **User Group Management**
- **GET, POST, DELETE** `/groups/managers`: Manage Manager group.  
- **GET, POST, DELETE** `/groups/delivery-crew`: Manage Delivery Crew group.  

---

## ⚙️ Advanced Features  

- **JWT Authentication**: Secure sessions with token-based authentication.  
- **Custom Middleware**: Authentication and authorization without external frameworks.  
- **MongoDB Integration**: Flexible and NoSQL database for dynamic data models.  
- **Kafka Logging**: Integrated Kafka for event and audit logging.  
- **ElasticSearch & Kibana**: Support for advanced search, analytics, and real-time monitoring/visualization via ElasticSearch and Kibana.  
- **Rate Limiting**: API throttling for authenticated and unauthenticated users.  
- **Sorting and Pagination**: Optimized responses for large datasets.  

---

## 🛠️ Tools and Technologies  

- **Language**: GoLang  
- **Database**: MongoDB  
- **Routing**: Gorilla Mux  
- **Password Security**: Bcrypt  
- **Mobile Frontend**: Flutter  
- **Containerization**: Docker, Docker Compose

---

## 🌟 Contribution  

We welcome contributions! To get started:  
1. Fork the repository.  
2. Create a new branch (`feature/your-feature-name`).  
3. Commit your changes and push.  
4. Submit a Pull Request for review.  

---
