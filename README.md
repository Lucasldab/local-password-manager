# Local Password Manager

A secure, local CLI password manager written in Rust, using Argon2id key derivation and an encrypted SQLite (SQLCipher) database.

---

## Features

- Local-only storage, no cloud or server involved  
- Argon2id for password-based key derivation  
- Encrypted vault using SQLCipher and SQLite  
- Command-line interface for managing credentials  
- Designed for security and simplicity

---

## Getting Started

### Prerequisites

- Rust and Cargo installed ([Installation guide](https://www.rust-lang.org/tools/install))  
- Git (to clone the repository)

This project bundles SQLCipher with the binary, so you do not need a system SQLCipher installation.

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/local-password-manager.git
cd local-password-manager
cargo build --release
```

---

## Usage

The CLI will prompt for your master passphrase as needed. Default DB path is `./vault.db3` unless `DATABASE_URL` is set.

Commands:

```bash
# Initialize a new encrypted vault (prompts for passphrase)
cargo run -- init

# Specify a custom DB path
cargo run -- init --db /path/to/vault.db3

# Add a credential (prompts for master passphrase and the credential password)
cargo run -- add --service github.com --username user123 [--notes "personal acct"] [--db /path/to/vault.db3]

# Retrieve credentials for a service
cargo run -- get --service github.com [--db /path/to/vault.db3]

# List all stored services
cargo run -- list [--db /path/to/vault.db3]
```

Environment variables (optional):

- `DATABASE_URL`: path to the SQLite/SQLCipher database (default: `./vault.db3`)
- `LOG_LEVEL`: `trace|debug|info|warn|error` (default: `info`)

Security notes:

- The database is encrypted at rest using SQLCipher with your master passphrase.
- Password fields are additionally encrypted with XChaCha20-Poly1305 using a key derived via Argon2id from your passphrase and a per-vault salt stored in `vault_metadata`.
- Each credential row stores a unique nonce for AEAD.

---

## Project Structure

- `src/`: Rust source code  
- `Cargo.toml`: Rust dependencies and metadata

---

## Contributing

Contributions are welcome! Please open issues or submit pull requests.

---

## License

MIT License © Lucas Lima de Aragão Barros

---

## Contact

Lucas Barros — lucasldabarros@gmail.com  
Project Link: https://github.com/Lucasldab/local-password-manager
