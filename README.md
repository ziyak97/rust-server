# Rust Server

This is a simple Rust server that uses the `axum` framework, `sqlx` for database access, and `PostgreSQL` as the database.

## Requirements

- Rust
- PostgreSQL

## Setup

1. Install the required dependencies.

2. Set up the database by running the initial migration.

3. Update the `.env` file with your database connection details.

## Running the Server

To run the server, use the `cargo run` command:

```cargo run```

The server will start and listen for incoming requests.

## Modules

The server includes several modules:

- `error`: Defines an `Error` enum and an `IntoResponse` implementation for handling errors.
- `http`: Defines routes and handlers for processing HTTP requests.
- `migrations`: Contains SQL migrations for setting up the database.

## Database Access

The server uses `sqlx` to interact with a `PostgreSQL` database. The database connection details are specified in the `.env` file.

## Migrations

The server includes an initial migration for setting up the database. These migrations are defined in the `migrations` module. They will be applied automatically when the server starts.
