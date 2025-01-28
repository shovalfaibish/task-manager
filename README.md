# Task Manager

Task Manager is a backend application built with Go that allows users to manage tasks. It includes features such as user authentication, task creation, updating, deletion, and reminders for upcoming deadlines.

## Features

- User authentication with JWT tokens
- Role-based access control (User and Admin roles)
- CRUD operations for tasks
- Task prioritization and deadlines
- Background job for task reminders
- Unit tests for various functionalities

## Getting Started

### Prerequisites

- Go 1.16 or later
- SQLite

### Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/yourusername/task-manager.git
    cd task-manager
    ```

2. Install dependencies:

    ```sh
    go mod tidy
    ```

3. Set up the database:

    ```sh
    go run main.go
    ```

### Running the Application

1. Start the application:

    ```sh
    go run main.go
    ```

2. The application will run on `http://localhost:8080`.

### API Endpoints

#### User Endpoints

- **POST /users**: Create a new user
- **POST /login**: Authenticate a user and generate a JWT token
- **PUT /users/:user_id/email**: Update a user's email (requires authentication)
- **PUT /users/:user_id/role**: Update a user's role (requires admin authentication)

#### Task Endpoints

- **POST /tasks**: Create a new task (requires authentication)
- **PUT /tasks/:task_id**: Update an existing task (requires authentication)
- **DELETE /tasks/:task_id**: Delete a task (requires admin authentication)
- **GET /tasks/user/:user_id**: Retrieve tasks for a specific user (requires authentication)
- **GET /tasks/upcoming**: Retrieve tasks with upcoming deadlines for the authenticated user (requires authentication)
- **GET /tasks/upcoming/all**: Retrieve tasks with upcoming deadlines for all users (requires admin authentication)

### Running Tests

1. Run the tests:

    ```sh
    go test ./...
    ```

### Project Structure

```
task-manager/
├── database/
│   └── db.go
├── routes/
│   ├── routes.go
│   ├── task.go
│   ├── user.go
│   └── routes_test.go
├── main.go
├── go.mod
├── go.sum
└── README.md
```
