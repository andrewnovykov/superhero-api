package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	"github.com/papapin/superhero/middleware"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var db *gorm.DB
var jwtSecret []byte

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Team struct {
	ID      uint        `gorm:"primaryKey" json:"id"`
	Title   string      `json:"title"`
	Picture string      `json:"picture"`
	Heroes  []Superhero `gorm:"foreignKey:TeamID" json:"heroes"`
}

type Superhero struct {
	ID          uint        `gorm:"primaryKey" json:"id"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Power       string      `json:"power"`
	Level       int         `json:"level"`
	Picture     string      `json:"picture"`
	TeamID      uint        `json:"team_id"`
	Team        Team        `json:"team"` // Include team information
	Allies      []Superhero `gorm:"many2many:superhero_allies;" json:"allies"`
	Foes        []Superhero `gorm:"many2many:superhero_foes;" json:"foes"`
}

func initDB() {
	dsn := "host=localhost user=papapin777 password=password dbname=superhero port=5432 sslmode=disable TimeZone=Asia/Shanghai"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	// Auto migrate the schema
	err = db.AutoMigrate(&Superhero{}, &Team{})
	if err != nil {
		log.Fatalf("failed to migrate database: %v", err)
	}
}

// Middleware to check if superuser is logged in
func superuserAuthRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the JWT token from the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Parse and validate the token
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Ensure the signing method is HMAC
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})

		// If the token is invalid or expired, return unauthorized
		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Allow the request to proceed
		next.ServeHTTP(w, r)
	})
}

// Handle superuser login
func login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var loginReq LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
			http.Error(w, "Cannot parse JSON", http.StatusBadRequest)
			return
		}

		log.Printf("Received username: %s password: %s", loginReq.Username, loginReq.Password)

		// Check if the username and password are correct
		if loginReq.Username != os.Getenv("SUPERUSER_USERNAME") || loginReq.Password != os.Getenv("SUPERUSER_PASSWORD") {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Generate JWT token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": loginReq.Username,
			"exp":      time.Now().Add(time.Hour * 72).Unix(), // Token expires in 72 hours
		})

		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		// Respond with the token
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
		return
	}

	http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
}

// Handle superuser logout
func logout(w http.ResponseWriter, r *http.Request) {
	// Invalidate the token by setting its expiration to a past date
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Logout successful"})
}

// Create a new team (superuser only)
func createTeam(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var team Team
		if err := json.NewDecoder(r.Body).Decode(&team); err != nil {
			http.Error(w, "Cannot parse JSON", http.StatusBadRequest)
			return
		}

		if err := db.Create(&team).Error; err != nil {
			http.Error(w, "Failed to create team", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(team)
		return
	}

	http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
}

// Update a team (superuser only)
func updateTeam(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		id := strings.TrimPrefix(r.URL.Path, "/admin/team/edit/")
		var team Team
		if err := db.First(&team, "id = ?", id).Error; err != nil {
			http.Error(w, "Team not found", http.StatusNotFound)
			return
		}

		if err := json.NewDecoder(r.Body).Decode(&team); err != nil {
			http.Error(w, "Cannot parse JSON", http.StatusBadRequest)
			return
		}

		if err := db.Save(&team).Error; err != nil {
			http.Error(w, "Failed to update team", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(team)
		return
	}

	http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
}

// Delete a team (superuser only)
func deleteTeam(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		id := strings.TrimPrefix(r.URL.Path, "/admin/team/delete/")
		if err := db.Delete(&Team{}, "id = ?", id).Error; err != nil {
			http.Error(w, "Failed to delete team", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Team deleted successfully"})
		return
	}

	http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
}

// Create a new superhero (superuser only)
func createSuperhero(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var superhero Superhero
		if err := json.NewDecoder(r.Body).Decode(&superhero); err != nil {
			http.Error(w, "Cannot parse JSON", http.StatusBadRequest)
			return
		}

		if err := db.Create(&superhero).Error; err != nil {
			http.Error(w, "Failed to create superhero", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(superhero)
		return
	}

	http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
}

// Update a superhero (superuser only)
func updateSuperhero(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		id := strings.TrimPrefix(r.URL.Path, "/admin/superhero/edit/")
		var superhero Superhero
		if err := db.First(&superhero, "id = ?", id).Error; err != nil {
			http.Error(w, "Superhero not found", http.StatusNotFound)
			return
		}

		if err := json.NewDecoder(r.Body).Decode(&superhero); err != nil {
			http.Error(w, "Cannot parse JSON", http.StatusBadRequest)
			return
		}

		if err := db.Save(&superhero).Error; err != nil {
			http.Error(w, "Failed to update superhero", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(superhero)
		return
	}

	http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
}

// Delete a superhero (superuser only)
func deleteSuperhero(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		id := strings.TrimPrefix(r.URL.Path, "/admin/superhero/delete/")
		if err := db.Delete(&Superhero{}, "id = ?", id).Error; err != nil {
			http.Error(w, "Failed to delete superhero", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Superhero deleted successfully"})
		return
	}

	http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
}

// Public route handlers
func getTeams(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var teams []Team
	if err := db.Preload("Heroes").Find(&teams).Error; err != nil {
		http.Error(w, "Failed to fetch teams", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(teams)
}

func getTeam(w http.ResponseWriter, r *http.Request) {
	// Extract the ID from the URL path
	id := strings.TrimPrefix(r.URL.Path, "/team/")
	if id == "" {
		http.Error(w, "ID is required", http.StatusBadRequest)
		return
	}

	var team Team
	if err := db.Preload("Heroes").First(&team, "id = ?", id).Error; err != nil {
		http.Error(w, "Failed to fetch team", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(team)
}

func getSuperheroes(w http.ResponseWriter, r *http.Request) {
	var superheroes []Superhero
	if err := db.Preload("Allies").Preload("Foes").Find(&superheroes).Error; err != nil {
		http.Error(w, "Failed to fetch superheroes", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(superheroes)
}

func getSuperhero(w http.ResponseWriter, r *http.Request) {
	log.Println("Received request for superhero with ID:", r.URL.Path)
	id := strings.TrimPrefix(r.URL.Path, "/superhero/")
	if id == "" {
		http.Error(w, "ID is required", http.StatusBadRequest)
		return
	}
	var superhero Superhero
	if err := db.Preload("Team").Preload("Allies").Preload("Foes").First(&superhero, "id = ?", id).Error; err != nil {
		http.Error(w, "Failed to fetch superhero", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(superhero)
}

func main() {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	// Initialize the JWT secret from environment variable
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))

	// Initialize the database
	initDB()

	router := http.NewServeMux()
	// Public API routes
	router.HandleFunc("/teams/", getTeams)
	router.HandleFunc("/team/", getTeam)
	router.HandleFunc("/superheroes/", getSuperheroes)
	router.HandleFunc("/superhero/", getSuperhero)
	router.HandleFunc("/login/", login)
	router.HandleFunc("/logout", logout)

	// Admin API routes for superuser (protected by middleware)

	router.HandleFunc("/admin/team/new/", createTeam)
	router.HandleFunc("/admin/team/edit/", updateTeam)
	router.HandleFunc("/admin/team/delete/", deleteTeam)
	router.HandleFunc("/admin/superhero/new/", createSuperhero)
	router.HandleFunc("/admin/superhero/edit/", updateSuperhero)
	router.HandleFunc("/admin/superhero/delete/", deleteSuperhero)

	http.Handle("/admin/", superuserAuthRequired(router))

	// Start the HTTP server
	log.Fatal(http.ListenAndServe(":8080", middleware.Logging(router)))
}
