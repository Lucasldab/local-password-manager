use anyhow::{Context, Result};
use rusqlite::{params, Connection, Row};
use rusqlite::OptionalExtension;

pub struct VaultMetadata {
    pub salt: Vec<u8>,
    pub kdf_iterations: u32,
    pub kdf_memory: u32,
    pub kdf_parallelism: u32,
}

pub struct Credential {
    pub username: String,
    pub password: Vec<u8>, // encrypted blob
    pub nonce: Vec<u8>,
}

pub fn connect(db_path: &str, passphrase: &str) -> Result<Connection> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open DB at {}", db_path))?;

    // Enable SQLCipher key with PRAGMA
    conn.pragma_update(None, "key", &passphrase)
        .context("Failed to set encryption key")?;

    // Initialize tables if not exist
    init_vault(&conn)?;

    Ok(conn)
}

pub fn init_vault(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS vault_metadata (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            salt BLOB NOT NULL,
            kdf_iterations INTEGER NOT NULL,
            kdf_memory INTEGER NOT NULL,
            kdf_parallelism INTEGER NOT NULL,
            aead_algorithm TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            password BLOB NOT NULL,
            nonce BLOB NOT NULL,
            notes TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_service ON credentials(service);
        ",
    )
    .context("Failed to create tables")?;

    Ok(())
}

pub fn insert_metadata_if_absent(
    conn: &Connection,
    salt: &[u8],
    kdf_iterations: u32,
    kdf_memory: u32,
    kdf_parallelism: u32,
    aead_algorithm: &str,
) -> Result<()> {
    let exists: Option<i32> = conn
        .query_row(
            "SELECT id FROM vault_metadata WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .context("Failed to check vault_metadata existence")?;

    if exists.is_none() {
        conn.execute(
            "INSERT INTO vault_metadata (id, salt, kdf_iterations, kdf_memory, kdf_parallelism, aead_algorithm)
             VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            params![salt, &kdf_iterations, &kdf_memory, &kdf_parallelism, &aead_algorithm],
        )
        .context("Failed to insert vault_metadata")?;
    }

    Ok(())
}

pub fn get_metadata(conn: &Connection) -> Result<VaultMetadata> {
    let mut stmt = conn.prepare(
        "SELECT salt, kdf_iterations, kdf_memory, kdf_parallelism
         FROM vault_metadata WHERE id = 1",
    )?;

    let meta = stmt
        .query_row([], |row| {
            Ok(VaultMetadata {
                salt: row.get(0)?,
                kdf_iterations: row.get(1)?,
                kdf_memory: row.get(2)?,
                kdf_parallelism: row.get(3)?,
            })
        })
        .context("Failed to read vault_metadata")?;

    Ok(meta)
}

pub fn add_credential(
    conn: &Connection,
    service: &str,
    username: &str,
    encrypted_password: &[u8],
    nonce: &[u8],
    notes: Option<String>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO credentials (service, username, password, nonce, notes, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        params![service, username, encrypted_password, nonce, notes],
    )
    .context("Failed to insert credential")?;

    Ok(())
}

pub fn get_credential(conn: &Connection, service: &str) -> Result<Option<Credential>> {
    let mut stmt = conn.prepare(
        "SELECT username, password, nonce
         FROM credentials WHERE service = ?1",
    )?;

    let mut rows = stmt.query(params![service])?;

    if let Some(row) = rows.next()? {
        Ok(Some(row_to_credential(row)?))
    } else {
        Ok(None)
    }
}

pub fn list_services(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT DISTINCT service FROM credentials")?;
    let services_iter = stmt.query_map([], |row| row.get(0))?;

    let mut services = Vec::new();
    for service in services_iter {
        services.push(service?);
    }
    Ok(services)
}

fn row_to_credential(row: &Row) -> Result<Credential> {
    Ok(Credential {
        username: row.get(0)?,
        password: row.get(1)?,
        nonce: row.get(2)?,
    })
}

