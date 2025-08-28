mod cli;
mod db;
mod crypto;
mod models;

use dotenvy::dotenv;
use std::env;
use anyhow::Result;

fn main() -> Result<()> {
    // Load .env
    dotenv().ok();

    // Read environment variables
    let log_level = env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into());

    // Init logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    // Run CLI
    cli::parse_args()
}

