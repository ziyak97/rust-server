mod config;
mod http;

use config::Config;
use sqlx::postgres::PgPoolOptions;
use redis;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // This returns an error if the `.env` file doesn't exist, but that's not what we want
    // since we're not going to use a `.env` file if we deploy this application.
    dotenv::dotenv().ok();

    // Initialize the logger.
    env_logger::init();

    // Parse our configuration from the environment.
    // This will exit with a help message if something is wrong.
    let config = Config::parse();

    // We create a single connection pool for SQLx that's shared across the whole application.
    // This saves us from opening a new connection for every API call, which is wasteful.
    let db: sqlx::Pool<sqlx::Postgres> = PgPoolOptions::new()
        // The default connection limit for a Postgres server is 100 connections, minus 3 for superusers.
        // Since we're using the default superuser we don't have to worry about this too much,
        // although we should leave some connections available for manual access.
        //
        // If you're deploying your application with multiple replicas, then the total
        // across all replicas should not exceed the Postgres connection limit.
        .max_connections(50)
        .connect(&config.database_url)
        .await
        .expect("could not connect to database_url");

    let kv_store_client = redis::Client::open(&*config.kv_url)?;
    let kv_store = kv_store_client.get_connection()?;

    // This embeds database migrations in the application binary so we can ensure the database
    // is migrated correctly on startup
    log::info!("Running database migrations");
    sqlx::migrate!().run(&db).await?;
    log::info!("Database migrations complete");

    // Finally, we spin up our API.
    http::serve(config, db, kv_store).await?;

      // Log that the server is running
      log::info!("HTTP server is running");

      Ok(())

}