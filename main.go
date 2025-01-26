package main

import (
    "github.com/gin-gonic/gin"
    "task-manager/database"
    "task-manager/routes"
)

func main() {
    database.Connect() // Connect to the database
    database.Migrate() // Run migrations


    router := gin.Default()

    // Setup routes
    routes.SetupRoutes(router)

    router.Run(":8080")
}
