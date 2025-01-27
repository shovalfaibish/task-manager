package main

import (
	"fmt"
	"log"
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

	router.Run(":8080")
}

func startReminderJob() {
	for {
		checkForUpcomingDeadlines()
		time.Sleep(1 * time.Hour) // Check every hour
	}
}

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
		displayTaskInCLI(id, title, deadline, userID)
	}
}

func displayTaskInCLI(id int, title string, deadline time.Time, userID int) {
	fmt.Printf("Reminder: Task '%s' with ID %d is due at %s for user ID %d\n", title, id, deadline.Format(time.RFC1123), userID)
}
