package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"math"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
    "strings"


	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"github.com/twilio/twilio-go"
	twilioApi "github.com/twilio/twilio-go/rest/api/v2010"

)

type User struct {
    Username string `json:"username"`
    Password string `json:"password"`
    Pmail string `json:"pmail"`
}

type Person struct {
    Username  string  `json:"username" bson:"username"`
    Pmail     string  `json:"pmail" bson:"pmail"`
    PhoneNumber string    `json:"phoneNubmer" bson:"phoneNumber"`
    Latitude  float64 `json:"latitude" bson:"latitude"`
    Longitude float64 `json:"longitude" bson:"longitude"`
}

// Vehicle represents a rental vehicle
type Vehicle struct {
    ID       string  `json:"id" bson:"_id,omitempty"`
    Owner    string  `json:"owner" bson:"owner"`
    Pmail    string  `json:"pmail" bson:"pmail"`
    Model    string  `json:"model" bson:"model"`
    Location string  `json:"location" bson:"location"`
    Available bool  `json:"available" bson:"available"`
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
    filter := bson.M{"pmail": user.Pmail}
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
    // Find around endpoint
// Function to calculate distance between two coordinates using Haversine formula
func calculateDistance(lat1, lon1, lat2, lon2 float64) float64 {
    const radius = 6371 // Earth radius in kilometers
    dLat := (lat2 - lat1) * (math.Pi / 180)
    dLon := (lon2 - lon1) * (math.Pi / 180)
    a := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(lat1*(math.Pi/180))*math.Cos(lat2*(math.Pi/180))*math.Sin(dLon/2)*math.Sin(dLon/2)
    c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
    distance := radius * c
    return distance
}

func PeopleWithinRadiusEndpoint(response http.ResponseWriter, request *http.Request) {
    response.Header().Set("Content-Type", "application/json")

    // Parse latitude and longitude from request JSON
    var reqBody struct {
        Latitude  string  `json:"latitude"`
        Longitude string  `json:"longitude"`
        Location  string  `json:"location"`
    }
    err := json.NewDecoder(request.Body).Decode(&reqBody)
    if err != nil {
        response.WriteHeader(http.StatusBadRequest)
        response.Write([]byte(`{"error": "Invalid request JSON"}`))
        return
    }

    // Convert latitude and longitude strings to float64
    lat, err := strconv.ParseFloat(reqBody.Latitude, 64)
    if err != nil {
        response.WriteHeader(http.StatusBadRequest)
        response.Write([]byte(`{"error": "Invalid latitude format"}`))
        return
    }
    lon, err := strconv.ParseFloat(reqBody.Longitude, 64)
    if err != nil {
        response.WriteHeader(http.StatusBadRequest)
        response.Write([]byte(`{"error": "Invalid longitude format"}`))
        return
    }

    // Connect to MongoDB and query for people within the radius
    var people []Person
    collection := client.Database("npdb").Collection("hireme")
    filter := bson.M{}
    cursor, err := collection.Find(context.Background(), filter)
    if err != nil {
        response.WriteHeader(http.StatusInternalServerError)
        response.Write([]byte(`{"error": "Error finding people"}`))
        return
    }
    defer cursor.Close(context.Background())
    for cursor.Next(context.Background()) {
        var person Person
        if err := cursor.Decode(&person); err != nil {
            response.WriteHeader(http.StatusInternalServerError)
            response.Write([]byte(`{"error": "Error decoding person"}`))
            return
        }
        // Calculate distance between person and given coordinates
        distance := calculateDistance(lat, lon, person.Latitude, person.Longitude)
        if distance <= 30 { // Check if within 30km radius
            people = append(people, person)
        }
    }
    if err := cursor.Err(); err != nil {
        response.WriteHeader(http.StatusInternalServerError)
        response.Write([]byte(`{"error": "Error iterating over people"}`))
        return
    }

    // Return people within the radius
    json.NewEncoder(response).Encode(people)
}


// POST JOB 
func PostJob(response http.ResponseWriter, request *http.Request) {
    response.Header().Set("Content-Type", "application/json")

    // Parse request body
    var job struct {
        Name      string `json:"username"`
        Pmail     string `json:"pmail"`
        PhoneNumber string `json:"phoneNumber"`
        Latitude  string `json:"latitude"`
        Longitude string `json:"longitude"`
        Location  string `json:"location"`
    }
    err := json.NewDecoder(request.Body).Decode(&job)
    if err != nil {
        response.WriteHeader(http.StatusBadRequest)
        response.Write([]byte(`{"error": "Invalid request JSON"}`))
        return
    }

    // Convert latitude and longitude strings to float64
    lat, err := strconv.ParseFloat(job.Latitude, 64)
    if err != nil {
        response.WriteHeader(http.StatusBadRequest)
        response.Write([]byte(`{"error": "Invalid latitude format"}`))
        return
    }
    lon, err := strconv.ParseFloat(job.Longitude, 64)
    if err != nil {
        response.WriteHeader(http.StatusBadRequest)
        response.Write([]byte(`{"error": "Invalid longitude format"}`))
        return
    }

    // Insert job into database
    collection := client.Database("npdb").Collection("hireme")
    _, err = collection.InsertOne(context.Background(), bson.M{
        "pmail":     job.Pmail,
        "username":  job.Name,
        "latitude":  lat,
        "longitude": lon,
        "phoneNumber" : job.PhoneNumber,
        "location":  job.Location,
    })
    if err != nil {
        response.WriteHeader(http.StatusInternalServerError)
        response.Write([]byte(`{"error": "Error adding job to database"}`))
        return
    }

    response.WriteHeader(http.StatusCreated)
    response.Write([]byte(`{"message": "Job added successfully"}`))
}

// ListAvailableVehiclesEndpoint lists all available rental vehicles
func ListAvailableVehiclesEndpoint(response http.ResponseWriter, request *http.Request) {
    response.Header().Set("Content-Type", "application/json")
    // Access "vehicles" collection
    collection := client.Database("npdb").Collection("vehicles")

    // Query for available vehicles
    cursor, err := collection.Find(context.Background(), bson.M{"available": true})
    if err != nil {
        log.Fatal(err)
    }
    defer cursor.Close(context.Background())

    // Fetch and encode available vehicles
    var vehicles []Vehicle
    if err := cursor.All(context.Background(), &vehicles); err != nil {
        log.Fatal(err)
    }
    json.NewEncoder(response).Encode(vehicles)
}

// RentOutVehicleEndpoint allows users to rent out their vehicles
func RentOutVehicleEndpoint(response http.ResponseWriter, request *http.Request) {
    response.Header().Set("Content-Type", "application/json")

    // Parse request body
    var vehicle Vehicle
    if err := json.NewDecoder(request.Body).Decode(&vehicle); err != nil {
        response.WriteHeader(http.StatusBadRequest)
        response.Write([]byte(`{"error": "Invalid request JSON"}`))
        return
    }

    // Access "vehicles" collection
    collection := client.Database("npdb").Collection("vehicles")

    // Insert new vehicle into collection
    _, err := collection.InsertOne(context.Background(), vehicle)
    if err != nil {
        response.WriteHeader(http.StatusInternalServerError)
        response.Write([]byte(`{"error": "` + err.Error() + `"}`))
        return
    }

    response.WriteHeader(http.StatusCreated)
    response.Write([]byte(`{"message": "Vehicle rented out successfully"}`))
}
//
// AddOwnerAndEmployee adds a new owner and employee to the database
func AddOwnerAndEmployee(ownerEmail string, employeeEmail string) error {
    // Connect to MongoDB
    collection := client.Database("npdb").Collection("hired")

    // Check if the owner already exists
    filter := bson.M{"ownerEmail": ownerEmail}
    var existingOwner struct {
        OwnerEmail string   `bson:"ownerEmail"`
        Employees  []string `bson:"employees"`
    }
    err := collection.FindOne(context.Background(), filter).Decode(&existingOwner)
    if err != nil {
        // If owner not found, insert a new entry for the owner with the employee
        _, err := collection.InsertOne(context.Background(), bson.M{
            "ownerEmail": ownerEmail,
            "employees":  []string{employeeEmail},
        })
        if err != nil {
            // If error occurred during insertion, return error
            return err
        }
        return nil
    }

    // If owner exists, check if employee already exists
    for _, e := range existingOwner.Employees {
        if e == employeeEmail {
            return errors.New("employee already exists for this owner")
        }
    }

    // Add employee to existing owner's data
    existingOwner.Employees = append(existingOwner.Employees, employeeEmail)

    // Update owner's data in MongoDB
    update := bson.M{"$set": bson.M{"employees": existingOwner.Employees}}
    _, err = collection.UpdateOne(context.Background(), filter, update)
    if err != nil {
        // If error occurred during update, return error
        return err
    }

    return nil
}

// AddOwnerAndEmployeeHandler handles HTTP requests to add a new owner and employee
func AddOwnerAndEmployeeHandler(response http.ResponseWriter, request *http.Request) {
    response.Header().Set("Content-Type", "application/json")

    // Parse request body
    var data struct {
        OwnerEmail   string `json:"ownerEmail"`
        EmployeeEmail string `json:"employeeEmail"`
    }
    err := json.NewDecoder(request.Body).Decode(&data)
    if err != nil {
        response.WriteHeader(http.StatusBadRequest)
        response.Write([]byte(`{"error": "Invalid request JSON"}`))
        return
    }

    // Call the function to add owner and employee
    err = AddOwnerAndEmployee(data.OwnerEmail, data.EmployeeEmail)
    if err != nil {
        response.WriteHeader(http.StatusInternalServerError)
        response.Write([]byte(`{"error": "Error adding owner and employee to database"}`))
        return
    }

    response.WriteHeader(http.StatusCreated)
    response.Write([]byte(`{"message": "Owner and employee added successfully"}`))
}
///////////

// EmailConfig stores email configuration
type EmailConfig struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
}

// TwilioConfig stores Twilio configuration
type TwilioConfig struct {
	AccountSID string `json:"accountSID"`
	AuthToken  string `json:"authToken"`
	From       string `json:"from"`
}

// Config stores both email and Twilio configurations
type Config struct {
	Email  EmailConfig  `json:"email"`
	Twilio TwilioConfig `json:"twilio"`
}

// MessageRequest represents the JSON request format
type MessageRequest struct {
	Pmail   string `json:"pmail"`
	Message string `json:"message"`
}

// SendMessageHandler handles HTTP requests to send messages
func SendMessageHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
    log.Println("Received message sending request.")
	// Parse request body
	var request MessageRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
    // Load environment variables from .env file
    if err := godotenv.Load(); err != nil {
        log.Fatalf("Error loading .env file: %v", err)
    }
	// Check if the contact information is an email address
	if strings.Contains(request.Pmail, "@") {
		// Send email
		config := Config{
			Email: EmailConfig{
				Host:     "smtp.example.com",
				Port:     "587",
				Username: os.Getenv("Username"),
				Password: os.Getenv("Password"),
				From:     os.Getenv("From"),
			},
		}
		if err := sendEmail(config, request.Pmail, request.Message); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		// Send SMS
        
		config := Config{
			Twilio: TwilioConfig{
				AccountSID: os.Getenv("AccountSID"),
				AuthToken:  os.Getenv("AuthToken"),
				From:       os.Getenv("FromT"),
			},
		}
		if err := sendSMS(config, request.Pmail, request.Message); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Respond with success message
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Message sent successfully"}`))
}

// sendEmail sends an email message using SMTP
func sendEmail(config Config, to, message string) error {
	auth := smtp.PlainAuth("", config.Email.Username, config.Email.Password, config.Email.Host)

	msg := []byte("To: " + to + "\r\n" +
		"Subject: Your Subject\r\n" +
		"\r\n" +
		message)

	addr := config.Email.Host + ":" + config.Email.Port
	if err := smtp.SendMail(addr, auth, config.Email.From, []string{to}, msg); err != nil {
		return err
	}
	return nil
}

// sendSMS sends an SMS message using Twilio
func sendSMS(config Config, to, message string) error {
	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: config.Twilio.AccountSID,
		Password: config.Twilio.AuthToken,
	})

	params := &twilioApi.CreateMessageParams{}
	params.SetTo(to)
	params.SetFrom(config.Twilio.From)
	params.SetBody(message)

	resp, err := client.Api.CreateMessage(params)
	if err != nil {
		return err
	}
	response, _ := json.Marshal(*resp)
	log.Println("Response: " + string(response))
	return nil
}
// driver code
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
	router.HandleFunc("/hireList", PeopleWithinRadiusEndpoint).Methods("POST")
	router.HandleFunc("/postJob", PostJob).Methods("POST")
	router.HandleFunc("/addRental", RentOutVehicleEndpoint).Methods("POST")
	router.HandleFunc("/listRental", ListAvailableVehiclesEndpoint).Methods("POST")
	router.HandleFunc("/hired", AddOwnerAndEmployeeHandler).Methods("POST")
    router.HandleFunc("/sendMessage", SendMessageHandler).Methods("POST")
	// Use CORS middleware to handle CORS
	handler := cors.Default().Handler(router)
    log.Fatal(http.ListenAndServe(":"+port, handler))
}
