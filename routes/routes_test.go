package routes

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"task-manager/database"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// setupTestDB initializes the test database
func setupTestDB(t *testing.T) {
	database.InitTestDB()
	t.Cleanup(database.CloseDB)
}

// createTestUser creates a test user in the database
func createTestUser(t *testing.T, router *gin.Engine) {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	database.DB.Exec("INSERT INTO users (id, name, email, password) VALUES (?, ?, ?, ?)", 1, "TestUser", "testuser@example.com", hashedPassword)
}

// loginTestUser logs in the test user and returns the JWT token
func loginTestUser(t *testing.T, router *gin.Engine) string {
	loginRequestBody := `{"email": "testuser@example.com", "password": "password"}`
	loginReq, _ := http.NewRequest("POST", "/login", bytes.NewBufferString(loginRequestBody))
	loginReq.Header.Set("Content-Type", "application/json")

	loginW := httptest.NewRecorder()
	router.ServeHTTP(loginW, loginReq)

	assert.Equal(t, http.StatusOK, loginW.Code)

	var loginResponse map[string]string
	json.Unmarshal(loginW.Body.Bytes(), &loginResponse)
	token := loginResponse["token"]

	assert.NotEmpty(t, token, "JWT token should not be empty")
	return token
}

// createTestAdmin creates a test admin user in the database
func createTestAdmin(t *testing.T, router *gin.Engine) {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	database.DB.Exec("INSERT INTO users (id, name, email, password, role) VALUES (?, ?, ?, ?, ?)", 1, "AdminUser", "admin@example.com", hashedPassword, "Admin")
}

// loginTestAdmin logs in the test admin user and returns the JWT token
func loginTestAdmin(t *testing.T, router *gin.Engine) string {
	loginRequestBody := `{"email": "admin@example.com", "password": "password"}`
	loginReq, _ := http.NewRequest("POST", "/login", bytes.NewBufferString(loginRequestBody))
	loginReq.Header.Set("Content-Type", "application/json")

	loginW := httptest.NewRecorder()
	router.ServeHTTP(loginW, loginReq)

	assert.Equal(t, http.StatusOK, loginW.Code)

	var loginResponse map[string]string
	json.Unmarshal(loginW.Body.Bytes(), &loginResponse)
	token := loginResponse["token"]

	assert.NotEmpty(t, token, "JWT token should not be empty")
	return token
}

// TestCreateUser tests the creation of a new user
func TestCreateUser(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/users", CreateUser)

	requestBody := `{"name": "TestUser", "email": "testuser@example.com", "password": "password", "role": "User"}`
	req, _ := http.NewRequest("POST", "/users", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), `"name":"TestUser"`)
	assert.Contains(t, w.Body.String(), `"email":"testuser@example.com"`)
}

// TestUserAuthentication tests user authentication and JWT token generation
func TestUserAuthentication(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/users", CreateUser)
	router.POST("/login", Login)

	createTestUser(t, router)

	token := loginTestUser(t, router)
	t.Log("JWT token received:", token)
}

// TestCreateTask tests the creation of a new task
func TestCreateTask(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)
	router.POST("/tasks", AuthMiddleware(), CreateTask)

	createTestUser(t, router)
	token := loginTestUser(t, router)

	requestBody := `{"title": "TestTask", "description": "TestDescription", "priority": "Medium", "user_id": 1}`
	req, _ := http.NewRequest("POST", "/tasks", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), `"title":"TestTask"`)
	assert.Contains(t, w.Body.String(), `"description":"TestDescription"`)
	assert.Contains(t, w.Body.String(), `"priority":"Medium"`)
}

// TestUpdateTask tests updating an existing task
func TestUpdateTask(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)
	router.PUT("/tasks/:task_id", AuthMiddleware(), UpdateTask)

	createTestUser(t, router)
	token := loginTestUser(t, router)

	database.DB.Exec("INSERT INTO tasks (id, title, description, user_id) VALUES (?, ?, ?, ?)", 1, "TestTask", "TestDescription", 1)

	requestBody := `{"title": "UpdatedTask", "description": "UpdatedDescription"}`
	req, _ := http.NewRequest("PUT", "/tasks/1", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"title":"UpdatedTask"`)
	assert.Contains(t, w.Body.String(), `"description":"UpdatedDescription"`)
}

// TestDeleteTask tests deleting a task
func TestDeleteTask(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)
	router.DELETE("/tasks/:task_id", AuthMiddleware(), DeleteTask)

	createTestUser(t, router)
	token := loginTestUser(t, router)

	database.DB.Exec("INSERT INTO tasks (id, title, description, user_id) VALUES (?, ?, ?, ?)", 1, "TestTask", "TestDescription", 1)

	req, _ := http.NewRequest("DELETE", "/tasks/1", nil)
	req.Header.Set("Authorization", token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"message":"Task deleted successfully"`)
}

// TestGetTasksByUser tests retrieving tasks for a specific user
func TestGetTasksByUser(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)
	router.GET("/tasks/user/:user_id", AuthMiddleware(), GetTasksByUser)

	createTestUser(t, router)
	token := loginTestUser(t, router)

	database.DB.Exec("INSERT INTO tasks (id, title, description, status, user_id) VALUES (?, ?, ?, ?, ?)", 1, "Task1", "Description1", "pending", 1)
	database.DB.Exec("INSERT INTO tasks (id, title, description, status, user_id) VALUES (?, ?, ?, ?, ?)", 2, "Task2", "Description2", "completed", 1)
	database.DB.Exec("INSERT INTO tasks (id, title, description, status, user_id) VALUES (?, ?, ?, ?, ?)", 3, "Task3", "Description3", "pending", 1)

	req, _ := http.NewRequest("GET", "/tasks/user/1", nil)
	req.Header.Set("Authorization", token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var tasks []map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &tasks)
	assert.NoError(t, err)

	expectedTasks := []map[string]interface{}{
		{"id": 1, "title": "Task1", "description": "Description1", "status": "pending"},
		{"id": 2, "title": "Task2", "description": "Description2", "status": "completed"},
		{"id": 3, "title": "Task3", "description": "Description3", "status": "pending"},
	}

	for i, expected := range expectedTasks {
		assert.Equal(t, expected["id"], int(tasks[i]["id"].(float64)))
		assert.Equal(t, expected["title"], tasks[i]["title"])
		assert.Equal(t, expected["description"], tasks[i]["description"])
		assert.Equal(t, expected["status"], tasks[i]["status"])
	}
}

// TestCreateTaskMissingFields tests creating a task with missing fields
func TestCreateTaskMissingFields(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)
	router.POST("/tasks", AuthMiddleware(), CreateTask)

	createTestUser(t, router)
	token := loginTestUser(t, router)

	requestBody := `{"title": "TestTask"}`
	req, _ := http.NewRequest("POST", "/tasks", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "'UserID' failed on the 'required' tag")
}

// TestUpdateTaskNotExist tests updating a non-existent task
func TestUpdateTaskNotExist(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)
	router.PUT("/tasks/:task_id", AuthMiddleware(), UpdateTask)

	createTestUser(t, router)
	token := loginTestUser(t, router)

	requestBody := `{"title": "UpdatedTask", "description": "UpdatedDescription"}`
	req, _ := http.NewRequest("PUT", "/tasks/999", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), `"error":"Task does not exist"`)
}

// TestUpdateTaskInvalidData tests updating a task with invalid data
func TestUpdateTaskInvalidData(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)
	router.PUT("/tasks/:task_id", AuthMiddleware(), UpdateTask)

	createTestUser(t, router)
	token := loginTestUser(t, router)

	database.DB.Exec("INSERT INTO tasks (id, title, description, user_id) VALUES (?, ?, ?, ?)", 1, "TestTask", "TestDescription", 1)

	requestBody := `{"title": ""}`
	req, _ := http.NewRequest("PUT", "/tasks/1", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), `"error":"At least one field (title, description, status, priority, deadline) must be provided"`)
}

// TestDeleteTaskNotExist tests deleting a non-existent task
func TestDeleteTaskNotExist(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)
	router.DELETE("/tasks/:task_id", AuthMiddleware(), DeleteTask)

	createTestUser(t, router)
	token := loginTestUser(t, router)

	req, _ := http.NewRequest("DELETE", "/tasks/999", nil)
	req.Header.Set("Authorization", token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), `"error":"Task does not exist"`)
}

// TestGetTasksByUserNoTasks tests retrieving tasks for a user with no tasks
func TestGetTasksByUserNoTasks(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)
	router.GET("/tasks/user/:user_id", AuthMiddleware(), GetTasksByUser)

	createTestUser(t, router)
	token := loginTestUser(t, router)

	req, _ := http.NewRequest("GET", "/tasks/user/1", nil)
	req.Header.Set("Authorization", token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "[]", w.Body.String())
}

// TestGetTasksByUserInvalidUserID tests retrieving tasks for an invalid user ID
func TestGetTasksByUserInvalidUserID(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)
	router.GET("/tasks/user/:user_id", AuthMiddleware(), GetTasksByUser)

	createTestUser(t, router)
	token := loginTestUser(t, router)

	req, _ := http.NewRequest("GET", "/tasks/user/invalid", nil)
	req.Header.Set("Authorization", token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), `"error":"User does not exist"`)
}

// TestGetTasksByStatusValid tests retrieving tasks by status
func TestGetTasksByStatusValid(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)
	router.GET("/tasks/status/:status", AuthMiddleware(), GetTasksByStatus)

	createTestUser(t, router)
	token := loginTestUser(t, router)

	database.DB.Exec("INSERT INTO tasks (id, title, description, status, user_id) VALUES (?, ?, ?, ?, ?)", 1, "Task1", "Description1", "pending", 1)

	req, _ := http.NewRequest("GET", "/tasks/status/pending", nil)
	req.Header.Set("Authorization", token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"title":"Task1"`)
}

// TestGetTasksByStatusNoTasks tests retrieving tasks by status when there are no tasks
func TestGetTasksByStatusNoTasks(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)
	router.GET("/tasks/status/:status", AuthMiddleware(), GetTasksByStatus)

	createTestUser(t, router)
	token := loginTestUser(t, router)

	req, _ := http.NewRequest("GET", "/tasks/status/pending", nil)
	req.Header.Set("Authorization", token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "[]", w.Body.String())
}

// TestUpdateUserEmail tests updating a user's email
func TestUpdateUserEmail(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)
	router.PUT("/users/:user_id/email", AuthMiddleware(), UpdateUserEmail)

	createTestUser(t, router)
	token := loginTestUser(t, router)

	requestBody := `{"email": "newemail@example.com"}`
	req, _ := http.NewRequest("PUT", "/users/1/email", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"message":"Email updated successfully"`)
}

// TestUpdateUserRole tests updating a user's role
func TestUpdateUserRole(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)
	router.PUT("/users/:user_id/role", AuthMiddleware(), AdminMiddleware(), UpdateUserRole)

	createTestAdmin(t, router)
	token := loginTestAdmin(t, router)

	createTestUser(t, router)

	requestBody := `{"role": "Admin"}`
	req, _ := http.NewRequest("PUT", "/users/1/role", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"message":"Role updated successfully"`)
}

// TestUpdateUserRoleUnauthorized tests updating a user's role without admin privileges
func TestUpdateUserRoleUnauthorized(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)
	router.PUT("/users/:user_id/role", AuthMiddleware(), AdminMiddleware(), UpdateUserRole)

	createTestUser(t, router)
	token := loginTestUser(t, router)

	requestBody := `{"role": "Admin"}`
	req, _ := http.NewRequest("PUT", "/users/1/role", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), `"error":"Forbidden"`)
}

// TestLogin tests user login
func TestLogin(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)

	createTestUser(t, router)

	token := loginTestUser(t, router)
	t.Log("JWT token received:", token)
}

// TestProtectedRoute tests accessing a protected route
func TestProtectedRoute(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)
	router.GET("/protected", AuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Protected route accessed"})
	})

	createTestUser(t, router)
	token := loginTestUser(t, router)

	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"message":"Protected route accessed"`)
}

// TestCreateUserDuplicateEmail tests creating a user with a duplicate email
func TestCreateUserDuplicateEmail(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/users", CreateUser)

	// Create the first user
	requestBody := `{"name": "TestUser", "email": "testuser@example.com", "password": "password", "role": "User"}`
	req, _ := http.NewRequest("POST", "/users", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	// Attempt to create a second user with the same email
	req, _ = http.NewRequest("POST", "/users", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Failed to create user")
}

// TestLoginInvalidCredentials tests logging in with invalid credentials
func TestLoginInvalidCredentials(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)

	// Attempt to log in with invalid credentials
	loginRequestBody := `{"email": "invalid@example.com", "password": "wrongpassword"}`
	req, _ := http.NewRequest("POST", "/login", bytes.NewBufferString(loginRequestBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid email or password")
}

// TestCreateTaskUnauthorized tests creating a task without authorization
func TestCreateTaskUnauthorized(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/tasks", AuthMiddleware(), CreateTask)

	// Attempt to create a task without a valid JWT token
	requestBody := `{"title": "TestTask", "description": "TestDescription", "user_id": 1}`
	req, _ := http.NewRequest("POST", "/tasks", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Authorization header required")
}

// TestUpdateTaskUnauthorized tests updating a task without authorization
func TestUpdateTaskUnauthorized(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.PUT("/tasks/:task_id", AuthMiddleware(), UpdateTask)

	// Attempt to update a task without a valid JWT token
	requestBody := `{"title": "UpdatedTask", "description": "UpdatedDescription"}`
	req, _ := http.NewRequest("PUT", "/tasks/1", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Authorization header required")
}

// TestDeleteTaskUnauthorized tests deleting a task without authorization
func TestDeleteTaskUnauthorized(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.DELETE("/tasks/:task_id", AuthMiddleware(), DeleteTask)

	// Attempt to delete a task without a valid JWT token
	req, _ := http.NewRequest("DELETE", "/tasks/1", nil)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Authorization header required")
}

// TestGetTasksByUserUnauthorized tests retrieving tasks by user without authorization
func TestGetTasksByUserUnauthorized(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.GET("/tasks/user/:user_id", AuthMiddleware(), GetTasksByUser)

	// Attempt to retrieve tasks by user without a valid JWT token
	req, _ := http.NewRequest("GET", "/tasks/user/1", nil)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Authorization header required")
}

// TestGetTasksByStatusUnauthorized tests retrieving tasks by status without authorization
func TestGetTasksByStatusUnauthorized(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.GET("/tasks/status/:status", AuthMiddleware(), GetTasksByStatus)

	// Attempt to retrieve tasks by status without a valid JWT token
	req, _ := http.NewRequest("GET", "/tasks/status/pending", nil)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Authorization header required")
}

// TestUpdateUserEmailUnauthorized tests updating a user's email without authorization
func TestUpdateUserEmailUnauthorized(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.PUT("/users/:user_id/email", AuthMiddleware(), UpdateUserEmail)

	// Attempt to update a user's email without a valid JWT token
	requestBody := `{"email": "newemail@example.com"}`
	req, _ := http.NewRequest("PUT", "/users/1/email", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Authorization header required")
}

// TestCreateTaskWithPriority tests creating a task with a priority
func TestCreateTaskWithPriority(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)
	router.POST("/tasks", AuthMiddleware(), CreateTask)

	createTestUser(t, router)
	token := loginTestUser(t, router)

	requestBody := `{"title": "TestTask", "description": "TestDescription", "priority": "High", "user_id": 1}`
	req, _ := http.NewRequest("POST", "/tasks", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), `"title":"TestTask"`)
	assert.Contains(t, w.Body.String(), `"description":"TestDescription"`)
	assert.Contains(t, w.Body.String(), `"priority":"High"`)
}

// TestUpdateTaskPriority tests updating a task's priority
func TestUpdateTaskPriority(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)
	router.PUT("/tasks/:task_id", AuthMiddleware(), UpdateTask)

	createTestUser(t, router)
	token := loginTestUser(t, router)

	database.DB.Exec("INSERT INTO tasks (id, title, description, priority, user_id) VALUES (?, ?, ?, ?, ?)", 1, "TestTask", "TestDescription", "Medium", 1)

	requestBody := `{"priority": "Low"}`
	req, _ := http.NewRequest("PUT", "/tasks/1", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"priority":"Low"`)
}

// TestCreateTaskWithDeadline tests creating a task with a deadline
func TestCreateTaskWithDeadline(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)
	router.POST("/tasks", AuthMiddleware(), CreateTask)

	createTestUser(t, router)
	token := loginTestUser(t, router)

	deadline := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	requestBody := `{"title": "TestTask", "description": "TestDescription", "priority": "High", "deadline": "` + deadline + `", "user_id": 1}`
	req, _ := http.NewRequest("POST", "/tasks", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), `"title":"TestTask"`)
	assert.Contains(t, w.Body.String(), `"description":"TestDescription"`)
	assert.Contains(t, w.Body.String(), `"priority":"High"`)
	assert.Contains(t, w.Body.String(), `"deadline":"`+deadline+`"`)
}

// TestUpdateTaskDeadline tests updating a task's deadline
func TestUpdateTaskDeadline(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)
	router.PUT("/tasks/:task_id", AuthMiddleware(), UpdateTask)

	createTestUser(t, router)
	token := loginTestUser(t, router)

	database.DB.Exec("INSERT INTO tasks (id, title, description, priority, user_id) VALUES (?, ?, ?, ?, ?)", 1, "TestTask", "TestDescription", "Medium", 1)

	deadline := time.Now().Add(48 * time.Hour).Format(time.RFC3339)
	requestBody := `{"deadline": "` + deadline + `"}`
	req, _ := http.NewRequest("PUT", "/tasks/1", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"deadline":"`+deadline+`"`)
}

// TestGetUpcomingDeadlines tests retrieving tasks with upcoming deadlines for the authenticated user
func TestGetUpcomingDeadlines(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)
	router.GET("/tasks/upcoming", AuthMiddleware(), GetUpcomingDeadlines)

	createTestUser(t, router)
	token := loginTestUser(t, router)

	// Set the deadline to be within the next hour
	deadline := time.Now().Add(30 * time.Minute).Format(time.RFC3339)
	database.DB.Exec("INSERT INTO tasks (id, title, description, priority, deadline, user_id) VALUES (?, ?, ?, ?, ?, ?)", 1, "TestTask", "TestDescription", "Medium", deadline, 1)

	req, _ := http.NewRequest("GET", "/tasks/upcoming", nil)
	req.Header.Set("Authorization", token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var tasks []map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &tasks)
	assert.NoError(t, err)

	assert.Len(t, tasks, 1)
	assert.Equal(t, "TestTask", tasks[0]["title"])
	assert.Equal(t, "TestDescription", tasks[0]["description"])
	assert.Equal(t, deadline, tasks[0]["deadline"])
}

// TestGetAllUpcomingDeadlines tests retrieving tasks with upcoming deadlines for all users (admin only)
func TestGetAllUpcomingDeadlines(t *testing.T) {
	setupTestDB(t)

	router := gin.Default()
	router.POST("/login", Login)
	router.GET("/tasks/upcoming/all", AuthMiddleware(), AdminMiddleware(), GetAllUpcomingDeadlines)

	createTestAdmin(t, router)
	token := loginTestAdmin(t, router)

	deadline := time.Now().Add(30 * time.Minute).Format(time.RFC3339)
	database.DB.Exec("INSERT INTO tasks (id, title, description, priority, deadline, user_id) VALUES (?, ?, ?, ?, ?, ?)", 1, "TestTask", "TestDescription", "Medium", deadline, 1)

	req, _ := http.NewRequest("GET", "/tasks/upcoming/all", nil)
	req.Header.Set("Authorization", token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var tasks []map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &tasks)
	assert.NoError(t, err)

	assert.Len(t, tasks, 1)
	assert.Equal(t, "TestTask", tasks[0]["title"])
	assert.Equal(t, "TestDescription", tasks[0]["description"])
	assert.Equal(t, deadline, tasks[0]["deadline"])
	assert.Equal(t, 1, int(tasks[0]["user_id"].(float64)))
}
