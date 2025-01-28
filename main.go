package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"task-manager/database"
	"task-manager/routes"

	"github.com/gin-gonic/gin"
)

func main() {
	database.Connect() // Connect to the database
	database.Migrate() // Run migrations

	router := gin.Default()

	// Setup routes
	routes.SetupRoutes(router)

	// Start the background job for reminders
	go startReminderJob()

	// Get the port from the environment variable
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Default port if not specified
	}

	router.Run(":" + port)
}

// startReminderJob starts a background job to check for upcoming deadlines
func startReminderJob() {
	for {
		checkForUpcomingDeadlines()
		time.Sleep(1 * time.Hour) // Check every hour
	}
}

// checkForUpcomingDeadlines checks for tasks with upcoming deadlines and displays them in the CLI
func checkForUpcomingDeadlines() {
	rows, err := database.DB.Query(`SELECT id, title, deadline, user_id FROM tasks WHERE deadline > datetime('now') AND deadline < datetime('now', '+1 hour')`)
	if err != nil {
		log.Println("Failed to retrieve tasks with upcoming deadlines:", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var title string
		var deadline time.Time
		var userID int

		if err := rows.Scan(&id, &title, &deadline, &userID); err != nil {
			log.Println("Failed to parse task:", err)
			continue
		}

		// Display the task in the CLI
		fmt.Printf("Reminder: Task '%s' with ID %d is due at %s for user ID %d\n", title, id, deadline.Format(time.RFC1123), userID)
	}
}
