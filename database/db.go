package database

import (
	"database/sql"
	"log"

	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

var DB *sql.DB

// Connect establishes a connection to the SQLite database
func Connect() {
	var err error

	// Open a connection to SQLite database file
	DB, err = sql.Open("sqlite", "task_manager.db")
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Verify the connection
	if err = DB.Ping(); err != nil {
		log.Fatalf("Failed to verify database connection: %v", err)
	}

	log.Println("Connected to database successfully!")
}

// Migrate creates the necessary tables in the database
func Migrate() {
	createUsersTable := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'User'
    );`

	createTasksTable := `
    CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'Pending',
        priority TEXT DEFAULT 'Medium',
        deadline DATETIME,
        user_id INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );`

	// Execute SQL statements to create tables
	_, err := DB.Exec(createUsersTable)
	if err != nil {
		log.Fatalf("Failed to create users table: %v", err)
	}

	_, err = DB.Exec(createTasksTable)
	if err != nil {
		log.Fatalf("Failed to create tasks table: %v", err)
	}

	log.Println("Database migration completed successfully!")
}

// InitTestDB initializes an in-memory database for testing
func InitTestDB() {
	var err error
	DB, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		log.Fatal("Failed to connect to test database:", err)
	}

	createTables := `
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'User'
    );
    CREATE TABLE tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'Pending',
        priority TEXT DEFAULT 'Medium',
        deadline DATETIME,
        user_id INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    `
	if _, err := DB.Exec(createTables); err != nil {
		log.Fatal("Failed to initialize test database schema:", err)
	}
}

// CloseDB closes the database connection
func CloseDB() {
	DB.Close()
}
