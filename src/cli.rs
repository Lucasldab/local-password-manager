use clap::{Parser, Subcommand};
use anyhow::{bail, Result};
use rpassword::prompt_password;

use crate::{crypto, db};

/// Local Password Manager CLI
#[derive(Parser)]
#[command(name = "pwmgr")]
#[command(about = "A local CLI password manager", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new encrypted vault
    Init {
        /// Optional database path (default: $DATABASE_URL or ./vault.db3)
        #[arg(short, long)]
        db: Option<String>,
    },

    /// Add a new credential
    Add {
        /// Service name (e.g., github.com)
        #[arg(short, long)]
        service: String,

        /// Username for the service
        #[arg(short, long)]
        username: String,

        /// Optional notes
        #[arg(short, long)]
        notes: Option<String>,

        /// Optional database path (default: $DATABASE_URL or ./vault.db3)
        #[arg(short = 'd', long = "db")]
        db: Option<String>,
    },

    /// Get credentials for a service
    Get {
        /// Service name to lookup
        #[arg(short, long)]
        service: String,

        /// Optional database path (default: $DATABASE_URL or ./vault.db3)
        #[arg(short = 'd', long = "db")]
        db: Option<String>,

        /// Print only the password to stdout (no labels)
        #[arg(long, default_value_t = false)]
        password_only: bool,
    },

    /// List all stored services
    List {
        /// Optional database path (default: $DATABASE_URL or ./vault.db3)
        #[arg(short = 'd', long = "db")]
        db: Option<String>,
    },
}

// Function to parse CLI args and handle commands
pub fn parse_args() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Init { db } => {
            let db_path = resolve_db_path(db.clone());
            log::info!("Using database: {}", db_path);
            println!("Initializing a new vault at {}", db_path);

            let passphrase = prompt_password("Set a master passphrase: ")?;
            let confirm = prompt_password("Confirm master passphrase: ")?;
            if passphrase != confirm {
                bail!("Passphrases do not match");
            }

            let conn = db::connect(&db_path, &passphrase)?;

            // If metadata absent, create it
            let salt = crypto::generate_salt(16);
            let (iters, mem, par) = default_kdf_params();
            db::insert_metadata_if_absent(&conn, &salt, iters, mem, par, crypto::AEAD_ALGORITHM)?;

            println!("Vault initialized.");
        }
        Commands::Add { service, username, notes, db } => {
            let db_path = resolve_db_path(db.clone());
            log::info!("Using database: {}", db_path);
            let passphrase = prompt_password("Master passphrase: ")?;
            let conn = db::connect(&db_path, &passphrase)?;

            let meta = db::get_metadata(&conn)?;
            let key = crypto::derive_key(
                &passphrase,
                &meta.salt,
                meta.kdf_iterations,
                meta.kdf_memory,
                meta.kdf_parallelism,
            )?;

            let pwd = prompt_password("Password to store: ")?;
            let (ciphertext, nonce) = crypto::encrypt_password(&key, pwd.as_bytes())?;
            db::add_credential(&conn, service, username, &ciphertext, &nonce, notes.clone())?;
            println!("Credential added.");
        }
        Commands::Get { service, db, password_only } => {
            let db_path = resolve_db_path(db.clone());
            log::info!("Using database: {}", db_path);
            let passphrase = prompt_password("Master passphrase: ")?;
            let conn = db::connect(&db_path, &passphrase)?;

            let meta = db::get_metadata(&conn)?;
            let key = crypto::derive_key(
                &passphrase,
                &meta.salt,
                meta.kdf_iterations,
                meta.kdf_memory,
                meta.kdf_parallelism,
            )?;

            if let Some(cred) = db::get_credential(&conn, service)? {
                let plaintext = crypto::decrypt_password(&key, &cred.nonce, &cred.password)?;
                let password_str = String::from_utf8_lossy(&plaintext);
                if *password_only {
                    println!("{}", password_str);
                } else {
                    println!("Username: {}", cred.username);
                    println!("Password: {}", password_str);
                }
            } else {
                println!("No credential found for service '{}'.", service);
            }
        }
        Commands::List { db } => {
            let db_path = resolve_db_path(db.clone());
            log::info!("Using database: {}", db_path);
            let passphrase = prompt_password("Master passphrase: ")?;
            let conn = db::connect(&db_path, &passphrase)?;
            let services = db::list_services(&conn)?;
            for s in services { println!("{}", s); }
        }
    }

    Ok(())
}

fn resolve_db_path(cli_db: Option<String>) -> String {
    if let Some(p) = cli_db { return p; }
    std::env::var("DATABASE_URL").unwrap_or_else(|_| "./vault.db3".to_string())
}

fn default_kdf_params() -> (u32, u32, u32) {
    // Reasonable defaults: 64 MiB, 3 iterations, parallelism 1
    (3, 64 * 1024, 1)
}

