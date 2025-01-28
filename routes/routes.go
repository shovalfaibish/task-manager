package routes

import (
	"log"
	"net/http"
	"strings"
	"task-manager/database"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

var jwtSecret = []byte("your_secret_key")

// SetupRoutes sets up the API routes
func SetupRoutes(router *gin.Engine) {
	// User routes
	router.POST("/users", CreateUser)
	router.POST("/login", Login)
	router.PUT("/users/:user_id/email", AuthMiddleware(), UpdateUserEmail)
	router.PUT("/users/:user_id/role", AuthMiddleware(), AdminMiddleware(), UpdateUserRole)

	// Task routes
	router.POST("/tasks", AuthMiddleware(), CreateTask)
	router.PUT("/tasks/:task_id", AuthMiddleware(), UpdateTask)
	router.DELETE("/tasks/:task_id", AuthMiddleware(), AdminMiddleware(), DeleteTask)
	router.GET("/tasks/user/:user_id", AuthMiddleware(), GetTasksByUser)
	router.GET("/tasks/upcoming", AuthMiddleware(), GetUpcomingDeadlines)
	router.GET("/tasks/upcoming/all", AuthMiddleware(), AdminMiddleware(), GetAllUpcomingDeadlines)
}

// AuthMiddleware handles JWT authentication
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Println("AuthMiddleware executed")
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			log.Println("Authorization header missing")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(strings.TrimPrefix(tokenString, "Bearer "), func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.NewValidationError("unexpected signing method", jwt.ValidationErrorSignatureInvalid)
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			log.Println("Token parsing error:", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		c.Set("email", claims["email"])
		c.Next()
	}
}

// AdminMiddleware handles admin authorization
func AdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		email, exists := c.Get("email")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		var role string
		err := database.DB.QueryRow(`SELECT role FROM users WHERE email = ?`, email).Scan(&role)
		if err != nil || role != "Admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
			c.Abort()
			return
		}

		c.Next()
	}
}
