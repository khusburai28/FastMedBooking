package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"github.com/joho/godotenv"
)

var client *mongo.Client
var jwtSecret []byte
var mongoURI string

func init() {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}
	
	// Get environment variables with defaults
	jwtSecretStr := os.Getenv("JWT_SECRET")
	if jwtSecretStr == "" {
		jwtSecretStr = "defaultsecret" // Default secret (for development only)
		log.Println("Warning: Using default JWT secret")
	}
	jwtSecret = []byte(jwtSecretStr)
	
	mongoURI = os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017" // Default URI
		log.Println("Warning: Using default MongoDB URI")
	}
}

type User struct {
	ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name      string             `json:"name" bson:"name"`
	Email     string             `json:"email" bson:"email"`
	Password  string             `json:"password" bson:"password"`
	Role      string             `json:"role" bson:"role"`
	CreatedAt time.Time          `json:"created_at" bson:"created_at"`
}

type Doctor struct {
	ID         primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	UserID     primitive.ObjectID `json:"user_id" bson:"user_id"`
	Specialty  string             `json:"specialty" bson:"specialty"`
	Location   string             `json:"location" bson:"location"`
	Bio        string             `json:"bio" bson:"bio"`
	Experience int                `json:"experience" bson:"experience"`
	Rating     float64            `json:"rating" bson:"rating"`
}

type Appointment struct {
	ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	PatientID primitive.ObjectID `json:"patient_id" bson:"patient_id"`
	DoctorID  primitive.ObjectID `json:"doctor_id" bson:"doctor_id"`
	DateTime  time.Time          `json:"date_time" bson:"date_time"`
	Status    string             `json:"status" bson:"status"`
	Notes     string             `json:"notes" bson:"notes"`
	CreatedAt time.Time          `json:"created_at" bson:"created_at"`
}

type MedicalRecord struct {
	ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	PatientID   primitive.ObjectID `json:"patient_id" bson:"patient_id"`
	DoctorID    primitive.ObjectID `json:"doctor_id" bson:"doctor_id"`
	Diagnosis   string             `json:"diagnosis" bson:"diagnosis"`
	Prescription string            `json:"prescription" bson:"prescription"`
	CreatedAt   time.Time          `json:"created_at" bson:"created_at"`
}

func main() {
	// MongoDB connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	clientOptions := options.Client().ApplyURI(
		mongoURI,
	)
	
	var err error
	client, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to MongoDB!")

	router := mux.NewRouter()

	// Auth routes
	router.HandleFunc("/api/signup", signUp).Methods("POST")
	router.HandleFunc("/api/login", login).Methods("POST")

	// Public routes
	router.HandleFunc("/api/doctors", getDoctors).Methods("GET")

	// Protected routes
	authRouter := router.PathPrefix("/api").Subrouter()
	authRouter.Use(authMiddleware)

	// Patient routes
	authRouter.HandleFunc("/appointments", createAppointment).Methods("POST")
	authRouter.HandleFunc("/appointments/patient/{id}", getPatientAppointments).Methods("GET")
	authRouter.HandleFunc("/medical-records/{patientId}", getMedicalRecords).Methods("GET")

	// Doctor routes
	authRouter.HandleFunc("/appointments/doctor/{id}", getDoctorAppointments).Methods("GET")
	authRouter.HandleFunc("/appointments/{id}", updateAppointment).Methods("PUT")

	// CORS setup
	cors := handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}),
	)

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", cors(router)))
}

func getCollection(collectionName string) *mongo.Collection {
	return client.Database("fastmedbooking").Collection(collectionName)
}

func signUp(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if user already exists
	usersCollection := getCollection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	var existingUser User
	err = usersCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&existingUser)
	if err == nil {
		http.Error(w, "Email already exists", http.StatusConflict)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	user.Password = string(hashedPassword)
	user.CreatedAt = time.Now()

	result, err := usersCollection.InsertOne(ctx, user)
	if err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	if user.Role == "doctor" {
		doctorsCollection := getCollection("doctors")
		_, err = doctorsCollection.InsertOne(ctx, bson.M{
			"user_id":    result.InsertedID,
			"created_at": time.Now(),
		})
		if err != nil {
			http.Error(w, "Error creating doctor profile", http.StatusInternalServerError)
			return
		}
	}

	json.NewEncoder(w).Encode(user)
}

func login(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}

	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	usersCollection := getCollection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	err = usersCollection.FindOne(ctx, bson.M{
		"email": credentials.Email,
		"role":  credentials.Role,
	}).Decode(&user)

	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":   user.ID.Hex(),
		"role": user.Role,
		"exp":  time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
		"role":  user.Role,
	})
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		r = r.WithContext(context.WithValue(r.Context(), "user", claims))
		next.ServeHTTP(w, r)
	})
}

func createAppointment(w http.ResponseWriter, r *http.Request) {
	var appointment Appointment
	err := json.NewDecoder(r.Body).Decode(&appointment)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	appointment.ID = primitive.NewObjectID()
	appointment.CreatedAt = time.Now()
	appointment.Status = "pending"

	appointmentsCollection := getCollection("appointments")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = appointmentsCollection.InsertOne(ctx, appointment)
	if err != nil {
		http.Error(w, "Error creating appointment", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(appointment)
}

func getPatientAppointments(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	patientID, err := primitive.ObjectIDFromHex(params["id"])
	if err != nil {
		http.Error(w, "Invalid patient ID", http.StatusBadRequest)
		return
	}

	appointmentsCollection := getCollection("appointments")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := appointmentsCollection.Find(ctx, bson.M{"patient_id": patientID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var appointments []Appointment
	if err = cursor.All(ctx, &appointments); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(appointments)
}

func updateAppointment(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	appointmentID, err := primitive.ObjectIDFromHex(params["id"])
	if err != nil {
		http.Error(w, "Invalid appointment ID", http.StatusBadRequest)
		return
	}

	var update struct {
		Status string `json:"status"`
	}
	err = json.NewDecoder(r.Body).Decode(&update)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	appointmentsCollection := getCollection("appointments")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = appointmentsCollection.UpdateOne(
		ctx,
		bson.M{"_id": appointmentID},
		bson.M{"$set": bson.M{"status": update.Status}},
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func getDoctors(w http.ResponseWriter, r *http.Request) {
	specialty := r.URL.Query().Get("specialty")
	location := r.URL.Query().Get("location")

	filter := bson.M{}
	if specialty != "" {
		filter["specialty"] = specialty
	}
	if location != "" {
		filter["location"] = location
	}

	doctorsCollection := getCollection("doctors")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := doctorsCollection.Find(ctx, filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var doctors []Doctor
	if err = cursor.All(ctx, &doctors); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(doctors)
}

func getMedicalRecords(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	patientID, err := primitive.ObjectIDFromHex(params["patientId"])
	if err != nil {
		http.Error(w, "Invalid patient ID", http.StatusBadRequest)
		return
	}

	medicalRecordsCollection := getCollection("medical_records")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := medicalRecordsCollection.Find(ctx, bson.M{"patient_id": patientID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var records []MedicalRecord
	if err = cursor.All(ctx, &records); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(records)
}

func getDoctorAppointments(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	doctorID, err := primitive.ObjectIDFromHex(params["id"])
	if err != nil {
		http.Error(w, "Invalid doctor ID", http.StatusBadRequest)
		return
	}

	appointmentsCollection := getCollection("appointments")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := appointmentsCollection.Find(ctx, bson.M{"doctor_id": doctorID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var appointments []Appointment
	if err = cursor.All(ctx, &appointments); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(appointments)
}