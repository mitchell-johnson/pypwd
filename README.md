# PyPWD - Python Password Manager

A simple, secure command-line password manager that stores encrypted passwords in a local SQLite database.

## Features

- **Embedded SQLite Database**: Fully self-contained with no external database setup required
- **User Account Management**: Multiple users can have separate encrypted vaults
- **Individual Password Encryption**: Each password is individually encrypted
- **Interactive UI**: Arrow key navigation and detailed entry views
- **Secure Input**: Passwords are entered securely without echoing to terminal

## Installation

1. Clone the repository:
```bash
git clone git@github.com:mitchell-johnson/pypwd.git
cd pypwd
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run PyPWD:
```bash
python pypwd.py
```

No additional database setup required - PyPWD uses an embedded SQLite database!

## Usage

### Basic Usage
```bash
python pypwd.py
```

## First Time Setup

When you run PyPWD for the first time, it automatically creates a secure SQLite database:

### Automatic Database Creation
1. PyPWD detects it's the first run and creates `~/.pypwd/pypwd.db`
2. No external database setup or credentials required
3. Database file permissions are automatically set to 600 (owner read/write only)

### User Account Creation
1. Enter a username for your account
2. If the username doesn't exist, you'll be prompted to create a new account
3. Set your master password (this encrypts all your stored passwords)
4. Confirm your master password

**Important**: Remember your master password! There is no way to recover it if forgotten.

## Menu Options

Once logged in with your master password, you'll see these options:

### 1. Add Password
- Enter the service/website name
- Enter your username for that service
- Enter your password (hidden input)
- Password is automatically encrypted and saved

### 2. List Passwords
- Arrow key navigation through password entries
- Press Enter to select and view detailed information
- Interactive detail view with multiple options

### 3. Search Passwords
- Search by service name or username
- Arrow key navigation through search results
- Press Enter to select and view detailed information

### 4. Exit
- Safely exits the program

## Interactive Features

When you select an entry in interactive mode, you'll see a detailed view with these options:

1. **Show password in cleartext** - Display the actual password with a security warning
2. **Export to file** - Save the password entry to a text file
3. **Add/Edit notes** - Add or modify notes for the entry
4. **Edit entry** - Modify service, username, or password interactively
5. **Back to list** - Return to the password list

### Navigation Controls
- **↑↓ Arrow Keys**: Navigate through lists
- **Enter**: Select highlighted item
- **q**: Go back/quit current view

## Example Session

```
$ python pypwd.py
Setting up PyPWD database for first time...
Creating secure local database...
Database setup completed successfully!

PyPWD - Secure Password Manager
===================================
Username: john
User 'john' not found. Create new account? (y/n): y
Creating new password manager account...
Password requirements:
- At least 10 characters long
Set master password: 
Confirm master password: 
User account 'john' created successfully!
Password manager loaded successfully!

Options:
1. Add password
2. List passwords
3. Search passwords
4. Exit

Select option (1-4): 1

Add new password entry:
Service/Website: gmail
Username: john@example.com
Password: 
Password saved successfully!
```

## Security Features

- **Unique Salt Per User**: Each user account uses a cryptographically secure random salt
- **PBKDF2 Key Derivation**: Uses 100,000 iterations for key strengthening  
- **Fernet Encryption**: Symmetric encryption using cryptographically secure methods
- **Secure Password Input**: Uses `getpass` module to hide password input
- **Password Length Requirements**: Enforces minimum 10-character master passwords
- **Rate Limiting**: Protection against brute force attacks (3 attempts, 30-second lockout)
- **Database Security**: Individual password encryption in embedded SQLite database
- **Interactive UI**: Arrow key navigation and detailed entry views
- **Notes Support**: Add notes and timestamps to password entries
- **Export Functionality**: Export individual passwords to text files
- **Multi-User Support**: Multiple users can maintain separate encrypted vaults

## Database Schema

PyPWD automatically creates a secure SQLite database (`~/.pypwd/pypwd.db`) with two tables:

1. **users**: Stores user accounts with hashed master passwords and unique salts
2. **passwords**: Stores individually encrypted password entries linked to users

All password data is encrypted using the user's master password before being stored in the database.

## Configuration

PyPWD stores its SQLite database in `~/.pypwd/pypwd.db` with restricted permissions (600). No additional configuration required - the database is completely self-contained and portable.

## Requirements

- Python 3.6+
- cryptography library
- SQLite (included with Python)

## Security Considerations

- Keep your master password secure and memorable
- Master passwords must be at least 10 characters long
- Regularly backup your encrypted database file (~/.pypwd/pypwd.db)
- Files are protected with restrictive permissions (owner read/write only)
- Rate limiting prevents brute force attacks (3 attempts, then 30-second lockout)
- Each user account uses a unique cryptographically secure salt
- Consider storing the encrypted database file in a secure location
- Use the secure search option to hide passwords when others might see your screen

## License

This project is open source and available under the MIT License.