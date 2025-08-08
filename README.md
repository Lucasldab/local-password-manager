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
- SQLite with SQLCipher support installed on your system  
- Git (to clone the repository)

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/local-password-manager.git
cd local-password-manager
cargo build --release
```

---

## Usage

(To be implemented)

Example commands:

```bash
# Initialize a new encrypted vault
pwmgr init

# Add a new credential
pwmgr add --service github.com --username user123

# Retrieve credentials
pwmgr get --service github.com

# List all stored services
pwmgr list
```

---

## Project Structure

- `src/`: Rust source code  
- `.github/workflows/`: CI workflow configuration  
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
