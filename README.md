### Task Manager

Welcome to the Task Manager project! This application is designed to help users manage their tasks efficiently with features like user roles, task prioritization, and more.

## Features

- **User Authentication**: Secure user authentication with JWT tokens.
- **User Roles and Permissions**: Different user roles (Admin, User) with role-based access control.
- **Task Management**: Create, update, delete, and view tasks.
- **Task Prioritization**: Set task priority (Low, Medium, High) and filter tasks based on priority.
- **Task Status**: Track task status (Pending, Completed).
- **Task Assignment**: Assign tasks to users.
- **Task Filtering**: Filter tasks by user and status.

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

   This will create the SQLite database and run the migrations.

### Running the Application

Start the application:

```sh
go run main.go
```

The application will be available at `http://localhost:8080`.

### API Endpoints

#### User Endpoints

- **POST /users**: Create a new user.
- **POST /login**: Authenticate a user and get a JWT token.
- **PUT /users/:user_id/email**: Update a user's email (requires authentication).
- **PUT /users/:user_id/role**: Update a user's role (requires admin authentication).

#### Task Endpoints

- **POST /tasks**: Create a new task (requires authentication).
- **PUT /tasks/:task_id**: Update a task (requires authentication).
- **DELETE /tasks/:task_id**: Delete a task (requires admin authentication).
- **GET /tasks/user/:user_id**: Get tasks by user (requires authentication).
- **GET /tasks/status/:status**: Get tasks by status (requires authentication).

### Running Tests

Run the tests to ensure everything is working correctly:

```sh
go test ./...
```
