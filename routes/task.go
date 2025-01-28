package routes

import (
	"log"
	"net/http"
	"strconv"
	"task-manager/database"
	"time"

	"github.com/gin-gonic/gin"
)

// Structs for request payloads
type CreateTaskRequest struct {
	Title       string    `json:"title" binding:"required"`
	Description string    `json:"description"`
	Priority    string    `json:"priority" binding:"required"`
	Deadline    time.Time `json:"deadline"`
	UserID      int       `json:"user_id" binding:"required"`
}

type UpdateTaskRequest struct {
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	Priority    string    `json:"priority"`
	Deadline    time.Time `json:"deadline"`
}

// userExists checks if a user exists in the database
func userExists(userID int) (bool, error) {
	var exists bool
	err := database.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE id = ?)`, userID).Scan(&exists)
	return exists, err
}

// taskExists checks if a task exists in the database
func taskExists(taskID string) (bool, error) {
	var exists bool
	err := database.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM tasks WHERE id = ?)`, taskID).Scan(&exists)
	return exists, err
}

// CreateTask handles the creation of a new task
func CreateTask(c *gin.Context) {
	var req CreateTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate if the user exists
	log.Println("Checking if user exists with userID:", req.UserID)
	exists, err := userExists(req.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate user existence"})
		return
	}

	if !exists {
		log.Println("User does not exist with userID:", req.UserID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "User does not exist"})
		return
	}

	// Insert task into the database
	result, err := database.DB.Exec(`INSERT INTO tasks (title, description, priority, deadline, user_id) VALUES (?, ?, ?, ?, ?)`,
		req.Title, req.Description, req.Priority, req.Deadline, req.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create task"})
		return
	}

	taskID, _ := result.LastInsertId()
	c.JSON(http.StatusCreated, gin.H{
		"id":          taskID,
		"title":       req.Title,
		"description": req.Description,
		"priority":    req.Priority,
		"deadline":    req.Deadline,
		"user_id":     req.UserID,
	})
}

// GetTasksByUser retrieves tasks for a specific user
func GetTasksByUser(c *gin.Context) {
	userID, _ := strconv.Atoi(c.Param("user_id"))

	exists, err := userExists(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate user existence"})
		return
	}

	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User does not exist"})
		return
	}

	rows, err := database.DB.Query(`SELECT id, title, description, status, priority FROM tasks WHERE user_id = ?`, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve tasks"})
		return
	}
	defer rows.Close()

	tasks := []gin.H{}
	for rows.Next() {
		var id int
		var title, description, status, priority string

		if err := rows.Scan(&id, &title, &description, &status, &priority); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse task"})
			return
		}

		tasks = append(tasks, gin.H{
			"id":          id,
			"title":       title,
			"description": description,
			"status":      status,
			"priority":    priority,
		})
	}

	c.JSON(http.StatusOK, tasks)
}

// UpdateTask handles updating an existing task
func UpdateTask(c *gin.Context) {
	taskID := c.Param("task_id")
	var req UpdateTaskRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	exists, err := taskExists(taskID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate task existence"})
		return
	}

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task does not exist"})
		return
	}

	// Check if at least one field is provided for update
	if req.Title == "" && req.Description == "" && req.Status == "" && req.Priority == "" && req.Deadline.IsZero() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one field (title, description, status, priority, deadline) must be provided"})
		return
	}

	// Build the update query dynamically based on provided fields
	query := "UPDATE tasks SET "
	args := []interface{}{}
	fields := map[string]interface{}{
		"title":       req.Title,
		"description": req.Description,
		"status":      req.Status,
		"priority":    req.Priority,
		"deadline":    req.Deadline,
	}

	for field, value := range fields {
		if value != "" && value != (time.Time{}) {
			query += field + " = ?, "
			args = append(args, value)
		}
	}
	query = query[:len(query)-2] // Remove the trailing comma and space
	query += " WHERE id = ?"
	args = append(args, taskID)

	_, err = database.DB.Exec(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update task"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":          taskID,
		"title":       req.Title,
		"description": req.Description,
		"status":      req.Status,
		"priority":    req.Priority,
		"deadline":    req.Deadline,
	})
}

// DeleteTask handles deleting a task
func DeleteTask(c *gin.Context) {
	taskID := c.Param("task_id")

	exists, err := taskExists(taskID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate task existence"})
		return
	}

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task does not exist"})
		return
	}

	_, err = database.DB.Exec(`DELETE FROM tasks WHERE id = ?`, taskID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete task"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Task deleted successfully"})
}

// GetTasksByStatus retrieves tasks by their status
func GetTasksByStatus(c *gin.Context) {
	status := c.Param("status")

	rows, err := database.DB.Query(`SELECT id, title, description, user_id FROM tasks WHERE status = ?`, status)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to retrieve tasks"})
		return
	}
	defer rows.Close()

	tasks := []gin.H{}
	for rows.Next() {
		var id int
		var title, description string
		var userID int

		if err := rows.Scan(&id, &title, &description, &userID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse task"})
			return
		}

		tasks = append(tasks, gin.H{
			"id":          id,
			"title":       title,
			"description": description,
			"user_id":     userID,
			"status":      status,
		})
	}

	c.JSON(http.StatusOK, tasks)
}

// GetUpcomingDeadlines retrieves tasks with upcoming deadlines for the authenticated user
func GetUpcomingDeadlines(c *gin.Context) {
	email, exists := c.Get("email")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var userID int
	err := database.DB.QueryRow(`SELECT id FROM users WHERE email = ?`, email).Scan(&userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user ID"})
		return
	}

	rows, err := database.DB.Query(`SELECT id, title, description, deadline FROM tasks WHERE user_id = ? AND deadline > datetime('now') AND deadline < datetime('now', '+1 day')`, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve tasks with upcoming deadlines"})
		return
	}
	defer rows.Close()

	tasks := []gin.H{}
	for rows.Next() {
		var id int
		var title, description string
		var deadline time.Time

		if err := rows.Scan(&id, &title, &description, &deadline); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse task"})
			return
		}

		tasks = append(tasks, gin.H{
			"id":          id,
			"title":       title,
			"description": description,
			"deadline":    deadline,
		})
	}

	c.JSON(http.StatusOK, tasks)
}

// GetAllUpcomingDeadlines retrieves tasks with upcoming deadlines for all users (admin only)
func GetAllUpcomingDeadlines(c *gin.Context) {
	rows, err := database.DB.Query(`SELECT id, title, description, deadline, user_id FROM tasks WHERE deadline > datetime('now') AND deadline < datetime('now', '+1 day')`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve tasks with upcoming deadlines"})
		return
	}
	defer rows.Close()

	tasks := []gin.H{}
	for rows.Next() {
		var id int
		var title, description string
		var deadline time.Time
		var userID int

		if err := rows.Scan(&id, &title, &description, &deadline, &userID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse task"})
			return
		}

		tasks = append(tasks, gin.H{
			"id":          id,
			"title":       title,
			"description": description,
			"deadline":    deadline,
			"user_id":     userID,
		})
	}

	c.JSON(http.StatusOK, tasks)
}
