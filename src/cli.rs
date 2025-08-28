use clap::{Parser, Subcommand};
use anyhow::{bail, Result};
use rpassword::prompt_password;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

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

    /// Edit an existing credential's password
    Edit {
        /// Service name to edit
        #[arg(short, long)]
        service: String,

        /// Optional database path (default: $DATABASE_URL or ./vault.db3)
        #[arg(short = 'd', long = "db")]
        db: Option<String>,
    },

    /// Delete a credential
    Delete {
        /// Service name to delete
        #[arg(short, long)]
        service: String,

        /// Optional database path (default: $DATABASE_URL or ./vault.db3)
        #[arg(short = 'd', long = "db")]
        db: Option<String>,
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

            // Ensure parent directory exists for the DB path
            ensure_parent_dir_exists(&db_path)?;

            let conn = db::connect(&db_path, &passphrase)?;

            // If metadata absent, create it
            let salt = crypto::generate_salt(16);
            let (iters, mem, par) = default_kdf_params();
            db::insert_metadata_if_absent(&conn, &salt, iters, mem, par, crypto::AEAD_ALGORITHM)?;

            // Cache master passphrase for the session (best-effort)
            if let Some(cache_file) = cache_file_for_db(&db_path) {
                let _ = write_cached_passphrase(&cache_file, &passphrase);
            }

            println!("Vault initialized.");
        }
        Commands::Add { service, username, notes, db } => {
            let db_path = resolve_db_path(db.clone());
            log::info!("Using database: {}", db_path);
            let passphrase = obtain_master_passphrase(&db_path)?;
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
            let passphrase = obtain_master_passphrase(&db_path)?;
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
        Commands::Edit { service, db } => {
            let db_path = resolve_db_path(db.clone());
            log::info!("Using database: {}", db_path);
            let passphrase = obtain_master_passphrase(&db_path)?;
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
                println!("Current username: {}", cred.username);
                let new_pwd = prompt_password("New password: ")?;
                let (ciphertext, nonce) = crypto::encrypt_password(&key, new_pwd.as_bytes())?;
                db::update_credential(&conn, service, &ciphertext, &nonce)?;
                println!("Credential updated.");
            } else {
                println!("No credential found for service '{}'.", service);
            }
        }
        Commands::Delete { service, db } => {
            let db_path = resolve_db_path(db.clone());
            log::info!("Using database: {}", db_path);
            let passphrase = obtain_master_passphrase(&db_path)?;
            let conn = db::connect(&db_path, &passphrase)?;

            if db::delete_credential(&conn, service)? {
                println!("Credential for '{}' deleted.", service);
            } else {
                println!("No credential found for service '{}'.", service);
            }
        }
        Commands::List { db } => {
            let db_path = resolve_db_path(db.clone());
            log::info!("Using database: {}", db_path);
            let passphrase = obtain_master_passphrase(&db_path)?;
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

// --- Session cache helpers (MVP): store master passphrase in XDG_RUNTIME_DIR ---

fn obtain_master_passphrase(db_path: &str) -> Result<String> {
    if let Some(cache_file) = cache_file_for_db(db_path) {
        if let Some(p) = read_cached_passphrase(&cache_file) {
            return Ok(p);
        }
        let p = prompt_password("Master passphrase: ")?;
        let _ = write_cached_passphrase(&cache_file, &p);
        return Ok(p);
    }
    // Fallback if no runtime dir available
    let p = prompt_password("Master passphrase: ")?;
    Ok(p)
}

fn cache_file_for_db(db_path: &str) -> Option<PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")?;
    let mut dir = PathBuf::from(base);
    dir.push("local-password-manager");
    let name = sanitize_filename(db_path);
    let mut file = dir.clone();
    file.push(format!("cache-{}", name));
    Some(file)
}

fn sanitize_filename(input: &str) -> String {
    input.chars().map(|c| match c {
        '/' => '_',
        '\\' => '_',
        ':' => '-',
        ' ' => '_',
        c if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' => c,
        _ => '_',
    }).collect()
}

fn read_cached_passphrase(path: &Path) -> Option<String> {
    let mut f = fs::File::open(path).ok()?;
    let mut buf = String::new();
    // Limit read size to 4096 bytes to avoid surprises
    let _ = (&mut f).take(4096).read_to_string(&mut buf).ok()?;
    let s = buf.trim_end_matches(['\n', '\r']).to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn write_cached_passphrase(path: &Path, pass: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(parent)?.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(parent, perms)?;
        }
    }
    let mut f = fs::File::create(path)?;
    #[cfg(unix)]
    {
        let mut perms = f.metadata()?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    f.write_all(pass.as_bytes())?;
    Ok(())
}

fn ensure_parent_dir_exists(db_path: &str) -> Result<()> {
    let path = Path::new(db_path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                let mut perms = fs::metadata(parent)?.permissions();
                perms.set_mode(0o700);
                fs::set_permissions(parent, perms)?;
            }
        }
    }
    Ok(())
}

