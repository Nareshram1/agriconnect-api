package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
    Username string `json:"username"`
    Password string `json:"password"`
    Pmail string `json:"pmail"`
}

var client *mongo.Client

func CreateUserEndpoint(response http.ResponseWriter, request *http.Request) {
    log.Println("req")
    response.Header().Set("Content-Type", "application/json")
    var user struct {
        Username string `json:"username"`
        Password string `json:"password"`
        Pmail    string `json:"pmail"`

    }
    _ = json.NewDecoder(request.Body).Decode(&user)

    // Check if either email or phone is provided
    // if user.Email == "" && user.Phone == "" {
    //     response.WriteHeader(http.StatusBadRequest)
    //     response.Write([]byte(`{"error": "Please provide email or phone"}`))
    //     return
    // }

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    if err != nil {
        response.WriteHeader(http.StatusInternalServerError)
        response.Write([]byte(`{"error": "Error hashing password"}`))
        return
    }

    // Choose which field to use for user creation (email or phone)
    newUser := User{
        Username: user.Username,
        Password: string(hashedPassword),
        Pmail: user.Pmail,
    }


    collection := client.Database("npdb").Collection("users")
    _, err = collection.InsertOne(context.Background(), newUser)
    if err != nil {
        response.WriteHeader(http.StatusInternalServerError)
        response.Write([]byte(`{"error": "` + err.Error() + `"}`))
        return
    }

    json.NewEncoder(response).Encode(newUser)
}

func LoginUserEndpoint(response http.ResponseWriter, request *http.Request) {
    response.Header().Set("Content-Type", "application/json")
    var user User
    _ = json.NewDecoder(request.Body).Decode(&user)

    collection := client.Database("npdb").Collection("users")
    filter := bson.M{"username": user.Username}
    var result User
    err := collection.FindOne(context.Background(), filter).Decode(&result)
    if err != nil {
        response.WriteHeader(http.StatusUnauthorized)
        response.Write([]byte(`{"error": "Invalid username or password"}`))
        return
    }

    // Check if the password matches
    if err := bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(user.Password)); err != nil {
        response.WriteHeader(http.StatusUnauthorized)
        response.Write([]byte(`{"error": "Invalid username or password"}`))
        return
    }
    // If login is successful, return a success message
    response.WriteHeader(http.StatusOK)
    response.Write([]byte(`{"message": "Login successful"}`))
}



func main() {
    // Load environment variables from .env file
    if err := godotenv.Load(); err != nil {
        log.Fatalf("Error loading .env file: %v", err)
    }

    // Get MongoDB URI from environment variable or use a default value
    mongoURI := os.Getenv("MONGO_URI")
    if mongoURI == "" {
        log.Fatal("MONGO_URI environment variable is not set")
    }
    // Set up MongoDB client
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
    clientOptions := options.Client().ApplyURI(mongoURI).SetServerAPIOptions(serverAPI)
    client, _= mongo.Connect(context.Background(), clientOptions)
	log.Println("Connected to database server.")
	port := os.Getenv("PORT")
	if port == "" {
		port = "5000" // Default port
	}

    router := mux.NewRouter()
    router.HandleFunc("/signup", CreateUserEndpoint).Methods("POST")
	router.HandleFunc("/login", LoginUserEndpoint).Methods("POST")
	// Use CORS middleware to handle CORS
	handler := cors.Default().Handler(router)
    log.Fatal(http.ListenAndServe(":"+port, handler))
}
