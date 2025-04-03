package main

import (
	"html/template"
	"net/http"
	"strconv"
	"sync"
)

type Appointment struct {
	ID          int
	Doctor      string
	Date        string
	Time        string
	Description string
	Booked      bool
	Patient     string
}

var (
	appointments []Appointment
	nextID       = 1
	mutex        sync.Mutex
)

var templates = template.Must(template.ParseGlob("templates/*.html"))

type DashboardData struct {
	Role   string
	Doctor string
	Slots  []Appointment
}

func main() {
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	http.HandleFunc("/add-slot", addSlotHandler)
	http.HandleFunc("/book", bookHandler)

	println("Server running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "home.html", nil)
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	role := r.URL.Query().Get("role")
	if role != "doctor" && role != "patient" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	data := DashboardData{
		Role: role,
	}

	mutex.Lock()
	defer mutex.Unlock()

	if role == "doctor" {
		doctor := r.URL.Query().Get("doctor")
		data.Doctor = doctor
		if doctor != "" {
			// Show all appointments created by this doctor
			for _, appt := range appointments {
				if appt.Doctor == doctor {
					data.Slots = append(data.Slots, appt)
				}
			}
		}
	} else if role == "patient" {
		// For patients, show only available (unbooked) appointments
		for _, appt := range appointments {
			if !appt.Booked {
				data.Slots = append(data.Slots, appt)
			}
		}
	}

	templates.ExecuteTemplate(w, "dashboard.html", data)
}

func addSlotHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	doctor := r.FormValue("doctor")
	date := r.FormValue("date")
	timeVal := r.FormValue("time")
	description := r.FormValue("description")

	if doctor == "" || date == "" || timeVal == "" {
		http.Error(w, "Missing fields", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	newAppointment := Appointment{
		ID:          nextID,
		Doctor:      doctor,
		Date:        date,
		Time:        timeVal,
		Description: description,
		Booked:      false,
	}
	nextID++
	appointments = append(appointments, newAppointment)
	mutex.Unlock()

	// Redirect back to the doctor's dashboard (preserving doctor name)
	http.Redirect(w, r, "/dashboard?role=doctor&doctor="+doctor, http.StatusSeeOther)
}

func bookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	apptIDStr := r.FormValue("id")
	patient := r.FormValue("patient")
	if apptIDStr == "" || patient == "" {
		http.Error(w, "Missing appointment ID or patient name", http.StatusBadRequest)
		return
	}

	apptID, err := strconv.Atoi(apptIDStr)
	if err != nil {
		http.Error(w, "Invalid appointment ID", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	// Find the appointment and mark it as booked
	for i, appt := range appointments {
		if appt.ID == apptID {
			if appt.Booked {
				http.Error(w, "Appointment already booked", http.StatusBadRequest)
				return
			}
			appointments[i].Booked = true
			appointments[i].Patient = patient
			break
		}
	}

	http.Redirect(w, r, "/dashboard?role=patient", http.StatusSeeOther)
}
