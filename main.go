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
	"bytes"
	"encoding/json"
	"mime/multipart"
	"encoding/base64"
	"strings"
	"io"
	"fmt"
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

type ChatRequest struct {
	Message string `json:"message"`
}

type DiseasePredictionRequest struct {
	Age           string `json:"age"`
	Gender        string `json:"gender"`
	Symptoms      string `json:"symptoms"`
	MedicalHistory string `json:"medical_history"`
}

type Medicine struct {
  Name    string `json:"name"`
  Dosage  string `json:"dosage"`
  Disease string `json:"disease"`
}

type PageData struct {
  User    string
  Role    string
  Results []Medicine
}

type GeminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
}

func askGemini(prompt string, file ...multipart.File) (string, error) {
	apiKey := os.Getenv("GEMINI_API_KEY")
	url := os.Getenv("GEMINI_API_URL") + "?key=" + apiKey

	var requestBody map[string]interface{}

	if len(file) > 0 && file[0] != nil {
		uploadedFile := file[0]
		defer uploadedFile.Close()

		fileData, err := io.ReadAll(uploadedFile)
		if err != nil {
			return "", fmt.Errorf("error reading uploaded file: %w", err)
		}

		// Determine the MIME type (you might need a more robust way)
		contentType := http.DetectContentType(fileData)

		requestBody = map[string]interface{}{
			"contents": []interface{}{
				map[string]interface{}{
					"parts": []interface{}{
						map[string]interface{}{
							"text": prompt,
						},
						map[string]interface{}{
							"inline_data": map[string]interface{}{
								"mime_type": contentType,
								"data":      base64.StdEncoding.EncodeToString(fileData),
							},
						},
					},
				},
			},
		}
	} else {
		requestBody = map[string]interface{}{
			"contents": []interface{}{
				map[string]interface{}{
					"parts": []interface{}{
						map[string]string{"text": prompt},
					},
				},
			},
		}
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("error marshaling request body: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %w", err)
	}

	var geminiResp GeminiResponse
	err = json.Unmarshal(body, &geminiResp)
	if err != nil {
		return "", fmt.Errorf("error unmarshaling response body: %w", err)
	}

	if len(geminiResp.Candidates) == 0 {
		return "No response from AI", nil
	}

	return geminiResp.Candidates[0].Content.Parts[0].Text, nil
}

func chatHandler(w http.ResponseWriter, r *http.Request) {
	_, _, loggedIn := getLoggedInUser(r)
	if !loggedIn {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	prompt := "Act as a medical expert and answer in 200 characters. Answer this health query in a professional but understandable way: " + req.Message
	response, err := askGemini(prompt)
	if err != nil {
		http.Error(w, "AI service error", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"response": response})
}

func predictDiseaseHandler(w http.ResponseWriter, r *http.Request) {
	_, _, loggedIn := getLoggedInUser(r)
	if !loggedIn {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req DiseasePredictionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	prompt := fmt.Sprintf(`Act as a medical expert. Predict possible diseases based on these details:
	- Age: %s
	- Gender: %s
	- Symptoms: %s
	- Medical History: %s
	
	Provide potential diagnoses in order of likelihood, possible next steps, and when to seek urgent care.
	Use clear language without medical jargon. Answer in 450 characters. `, req.Age, req.Gender, req.Symptoms, req.MedicalHistory)

	response, err := askGemini(prompt)
	if err != nil {
		http.Error(w, "AI service error", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"response": response})
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
	http.HandleFunc("/book_ambulance", bookAmbulanceHandler)
	http.HandleFunc("/buy_medicine", buyMedicineHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	http.HandleFunc("/add-slots-batch", addSlotsBatchHandler)
	http.HandleFunc("/book", bookHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/chat", chatHandler)
	http.HandleFunc("/predict-disease", predictDiseaseHandler)

	log.Println("Server running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func bookAmbulanceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "book_ambulance.html", nil)
		return		
	}

	if r.Method == http.MethodPost {
		// Handle ambulance booking logic here
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func buyMedicineHandler(w http.ResponseWriter, r *http.Request) {
  switch r.Method {
  case http.MethodGet:
    templates.ExecuteTemplate(w, "buy_medicine.html", nil)
    return

  case http.MethodPost:
    // 1) Read uploaded file
    file, _, err := r.FormFile("prescription")
    if err != nil {
      http.Error(w, "Failed to read file: "+err.Error(), http.StatusBadRequest)
      return
    }
    defer file.Close()

	// 3) Build prompt for Gemini
	prompt := `
	Analyze the provided prescription file and extract a JSON array of objects.
	Each object should have exactly the fields "name", "dosage", and "disease".
	Respond with *only* the JSON array—no backticks, no markdown, no commentary. And Based on the Medicine name, give the "disease" name (in 1-2 words) and also recommend the "dosage" field (if not specified, in 1-2 words).
	`

    // 4) Call Gemini
    response, err := askGemini(prompt, file)
    if err != nil {
      http.Error(w, "GPT error: "+err.Error(), http.StatusInternalServerError)
      return
    }

	clean := strings.TrimSpace(response)

	if strings.HasPrefix(clean, "```json") {
		clean = strings.TrimPrefix(clean, "```json")
	} else if strings.HasPrefix(clean, "```") {
		clean = strings.TrimPrefix(clean, "```")
	}

	clean = strings.Trim(clean, "`")
	clean = strings.TrimSpace(clean)

    // 5) Parse JSON into Go structs
    var meds []Medicine
    if err := json.Unmarshal([]byte(clean), &meds); err != nil {
      http.Error(w, "Failed to parse GPT JSON: "+err.Error(), http.StatusInternalServerError)
      return
    }

    // 6) Render template with results
    data := PageData{
      User:    "",        
      Role:    "",        
      Results: meds,
    }
    templates.ExecuteTemplate(w, "buy_medicine.html", data)
    return

  default:
    http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
  }
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

func addSlotsBatchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	username, role, loggedIn := getLoggedInUser(r)
	if !loggedIn || role != "doctor" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	days := r.Form["days"]
	startTime := r.FormValue("startTime")
	endTime := r.FormValue("endTime")
	slotDuration := r.FormValue("slotDuration")
	description := r.FormValue("description")

	if len(days) == 0 || startTime == "" || endTime == "" || slotDuration == "" {
		http.Error(w, "Missing fields", http.StatusBadRequest)
		return
	}

	duration, err := time.ParseDuration(slotDuration + "m")
	if err != nil {
		http.Error(w, "Invalid slot duration", http.StatusBadRequest)
		return
	}

	startTimeParsed, err := time.Parse("15:04", startTime)
	if err != nil {
		http.Error(w, "Invalid start time", http.StatusBadRequest)
		return
	}

	endTimeParsed, err := time.Parse("15:04", endTime)
	if err != nil {
		http.Error(w, "Invalid end time", http.StatusBadRequest)
		return
	}

	if endTimeParsed.Before(startTimeParsed) {
		http.Error(w, "End time must be after start time", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	appointments := []interface{}{}

	for _, day := range days {
		slotTime := startTimeParsed
		for slotTime.Before(endTimeParsed) {
			newAppointment := Appointment{
				Doctor:      username,
				Date:        day,
				Time:        slotTime.Format("15:04"),
				Description: description,
				Booked:      false,
				Patient:     "",
			}
			appointments = append(appointments, newAppointment)
			slotTime = slotTime.Add(duration)
		}
	}

	if len(appointments) > 0 {
		_, err = apptColl.InsertMany(ctx, appointments)
		if err != nil {
			http.Error(w, "Failed to add appointments", http.StatusInternalServerError)
			return
		}
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
