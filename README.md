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

### 4. Exit
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
4. Exit

Select option (1-4): 1

Add new password entry:
Service/Website: gmail
Username: john@example.com
Password: 
Password saved successfully!
```

## Security Features

- **PBKDF2 Key Derivation**: Uses 100,000 iterations for key strengthening
- **Fernet Encryption**: Symmetric encryption using cryptographically secure methods
- **Secure Password Input**: Uses `getpass` module to hide password input
- **Local Storage Only**: Passwords never leave your local machine

## File Format

The program creates an encrypted file (default: `passwords.enc`) that contains your password data. This file is completely encrypted and cannot be read without the master password.

## Requirements

- Python 3.6+
- cryptography library

## Security Considerations

- Keep your master password secure and memorable
- Regularly backup your encrypted password file
- The program uses a fixed salt for simplicity - in production environments, consider using unique salts per file
- Consider storing the encrypted file in a secure location

## License

This project is open source and available under the MIT License.