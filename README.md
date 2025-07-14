# PyPWD - Python Password Manager

A simple, secure command-line password manager that stores encrypted passwords in a local file.

## Features

- **Encrypted Storage**: Uses PBKDF2 key derivation with Fernet encryption
- **Master Password Protection**: Single master password secures all stored passwords
- **Simple CLI Interface**: Easy-to-use menu-driven interface
- **Search Functionality**: Find passwords by service name or username
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

## Usage

### Basic Usage
```bash
python pypwd.py
```

### Custom Password File
```bash
python pypwd.py my_passwords.enc
```

## First Time Setup

When you run the program for the first time, it will guide you through creating a new encrypted password file:

1. The program will ask if you want to create a new password file
2. Set your master password (this encrypts all your stored passwords)
3. Confirm your master password

**Important**: Remember your master password! There is no way to recover it if forgotten.

## Menu Options

Once logged in with your master password, you'll see these options:

### 1. Add Password
- Enter the service/website name
- Enter your username for that service
- Enter your password (hidden input)
- Password is automatically encrypted and saved

### 2. List Passwords
- Shows all stored passwords
- Passwords are masked with asterisks for security
- Displays service name and username

### 3. Search Passwords
- Search by service name or username
- Shows matching entries with actual passwords visible
- Case-insensitive search

### 4. Edit Password
- Select an entry by number to edit
- Modify service name, username, or password
- Leave fields blank to keep current values
- Changes are automatically encrypted and saved

### 5. Exit
- Safely exits the program

## Example Session

```
$ python pypwd.py
Password file 'passwords.enc' not found.
Create new password file? (y/n): y
Creating new password manager file...
Set master password: 
Confirm master password: 
Password file 'passwords.enc' created successfully!
Enter master password: 
Password manager loaded successfully!

Options:
1. Add password
2. List passwords
3. Search passwords
4. Edit password
5. Exit

Select option (1-5): 1

Add new password entry:
Service/Website: gmail
Username: john@example.com
Password: 
Password saved successfully!
```

## Security Features

- **Unique Salt Per File**: Each password file uses a cryptographically secure random salt
- **PBKDF2 Key Derivation**: Uses 100,000 iterations for key strengthening
- **Fernet Encryption**: Symmetric encryption using cryptographically secure methods
- **Secure Password Input**: Uses `getpass` module to hide password input
- **Password Strength Requirements**: Enforces strong master passwords
- **Rate Limiting**: Protection against brute force attacks (3 attempts, 30-second lockout)
- **Restrictive File Permissions**: Password files are set to owner-only access (600)
- **Path Traversal Protection**: Validates filenames to prevent directory traversal attacks
- **Secure Search**: Option to hide passwords in search results
- **Local Storage Only**: Passwords never leave your local machine

## File Format

The program creates an encrypted file (default: `passwords.enc`) that contains your password data. This file is completely encrypted and cannot be read without the master password.

## Requirements

- Python 3.6+
- cryptography library

## Security Considerations

- Keep your master password secure and memorable
- Master passwords must meet strength requirements (8+ chars, mixed case, numbers, special chars)
- Regularly backup your encrypted password file
- Files are protected with restrictive permissions (owner read/write only)
- Rate limiting prevents brute force attacks (3 attempts, then 30-second lockout)
- Each password file uses a unique cryptographically secure salt
- Consider storing the encrypted file in a secure location
- Use the secure search option to hide passwords when others might see your screen

## License

This project is open source and available under the MIT License.