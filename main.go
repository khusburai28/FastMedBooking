package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"
	"os"
	"github.com/joho/godotenv"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type User struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	Username string             `bson:"username"`
	Password string             `bson:"password"` // Stored as SHA256 hash
	Role     string             `bson:"role"`     // "doctor" or "patient"
}

type Appointment struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"`
	Doctor      string             `bson:"doctor"`
	Date        string             `bson:"date"`
	Time        string             `bson:"time"`
	Description string             `bson:"description"`
	Booked      bool               `bson:"booked"`
	Patient     string             `bson:"patient"`
}

var (
	mutex     sync.Mutex
	client    *mongo.Client
	usersColl *mongo.Collection
	apptColl  *mongo.Collection
)

var templates = template.Must(template.ParseGlob("templates/*.html"))

func getMongoURI() string {
	// Load .env file
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: Error loading .env file:", err)
	}
	
	// Get MongoDB URI from environment variable
	mongoURI := os.Getenv("MONGODB_URI")
	if mongoURI == "" {
		log.Println("MONGODB_URI not found in .env, using default")
		return "mongodb://localhost:27017"
	}
	
	return mongoURI
}

type DashboardData struct {
	Role   string
	Doctor string
	Slots  []Appointment
	User   string
}

func main() {
	// Connect to MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	clientOptions := options.Client().ApplyURI(getMongoURI())
	var err error
	client, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	
	// Check the connection
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Connected to MongoDB!")
	
	// Get database collections
	db := client.Database("appointment_system")
	usersColl = db.Collection("users")
	apptColl = db.Collection("appointments")
	
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	http.HandleFunc("/add-slot", addSlotHandler)
	http.HandleFunc("/book", bookHandler)
	http.HandleFunc("/logout", logoutHandler)

	log.Println("Server running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	templates.ExecuteTemplate(w, "home.html", nil)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "register.html", nil)
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		role := r.FormValue("role")

		if username == "" || password == "" || (role != "doctor" && role != "patient") {
			http.Error(w, "Invalid registration data", http.StatusBadRequest)
			return
		}

		// Check if user already exists
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		var existingUser User
		err := usersColl.FindOne(ctx, bson.M{"username": username}).Decode(&existingUser)
		if err == nil {
			http.Error(w, "Username already exists", http.StatusBadRequest)
			return
		}

		// Create new user
		hashedPassword := hashPassword(password)
		newUser := User{
			Username: username,
			Password: hashedPassword,
			Role:     role,
		}

		_, err = usersColl.InsertOne(ctx, newUser)
		if err != nil {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "login.html", nil)
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		
		if username == "" || password == "" {
			http.Error(w, "Missing username or password", http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		var user User
		err := usersColl.FindOne(ctx, bson.M{"username": username}).Decode(&user)
		if err != nil || user.Password != hashPassword(password) {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		// Create session (using cookies for simplicity)
		http.SetCookie(w, &http.Cookie{
			Name:    "username",
			Value:   username,
			Path:    "/",
			Expires: time.Now().Add(24 * time.Hour),
		})

		http.SetCookie(w, &http.Cookie{
			Name:    "role",
			Value:   user.Role,
			Path:    "/",
			Expires: time.Now().Add(24 * time.Hour),
		})

		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:    "username",
		Value:   "",
		Path:    "/",
		Expires: time.Now().Add(-time.Hour),
	})
	http.SetCookie(w, &http.Cookie{
		Name:    "role",
		Value:   "",
		Path:    "/",
		Expires: time.Now().Add(-time.Hour),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func getLoggedInUser(r *http.Request) (string, string, bool) {
	userCookie, err := r.Cookie("username")
	if err != nil {
		return "", "", false
	}
	
	roleCookie, err := r.Cookie("role")
	if err != nil {
		return "", "", false
	}
	
	return userCookie.Value, roleCookie.Value, true
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	username, role, loggedIn := getLoggedInUser(r)
	if !loggedIn {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	data := DashboardData{
		Role: role,
		User: username,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if role == "doctor" {
		data.Doctor = username
		// Show all appointments created by this doctor
		cursor, err := apptColl.Find(ctx, bson.M{"doctor": username})
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		defer cursor.Close(ctx)
		
		if err = cursor.All(ctx, &data.Slots); err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
	} else if role == "patient" {
		// For patients, show only available (unbooked) appointments
		cursor, err := apptColl.Find(ctx, bson.M{"booked": false})
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		defer cursor.Close(ctx)
		
		if err = cursor.All(ctx, &data.Slots); err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
	}

	templates.ExecuteTemplate(w, "dashboard.html", data)
}

func addSlotHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	username, role, loggedIn := getLoggedInUser(r)
	if !loggedIn || role != "doctor" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	date := r.FormValue("date")
	timeVal := r.FormValue("time")
	description := r.FormValue("description")

	if date == "" || timeVal == "" {
		http.Error(w, "Missing fields", http.StatusBadRequest)
		return
	}

	newAppointment := Appointment{
		Doctor:      username,
		Date:        date,
		Time:        timeVal,
		Description: description,
		Booked:      false,
		Patient:     "",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := apptColl.InsertOne(ctx, newAppointment)
	if err != nil {
		http.Error(w, "Failed to add appointment", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func bookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	username, role, loggedIn := getLoggedInUser(r)
	if !loggedIn || role != "patient" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	apptIDStr := r.FormValue("id")
	if apptIDStr == "" {
		http.Error(w, "Missing appointment ID", http.StatusBadRequest)
		return
	}

	apptID, err := primitive.ObjectIDFromHex(apptIDStr)
	if err != nil {
		http.Error(w, "Invalid appointment ID", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Find and update the appointment
	result, err := apptColl.UpdateOne(
		ctx,
		bson.M{"_id": apptID, "booked": false},
		bson.M{"$set": bson.M{"booked": true, "patient": username}},
	)

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if result.ModifiedCount == 0 {
		http.Error(w, "Appointment already booked or not found", http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
