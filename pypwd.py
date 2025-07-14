#!/usr/bin/env python3

import json
import os
import sys
import getpass
import secrets
import time
import re
import curses
import datetime
import mysql.connector
from mysql.connector import Error
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class PasswordManager:
    def __init__(self):
        # Internal database configuration
        self.db_host = os.getenv('PYPWD_DB_HOST', 'localhost')
        self.db_port = int(os.getenv('PYPWD_DB_PORT', '3306'))
        self.db_name = 'pypwd_secure'
        self.db_user = 'pypwd_app'
        self.db_password = self._generate_db_password()
        
        self.connection = None
        self.salt = None
        self.user_id = None
        self.failed_attempts = 0
        self.last_attempt_time = 0
        self.max_attempts = 3
        self.lockout_duration = 30  # seconds
        
        # Initialize database on first run
        self._setup_database()
        
    def _generate_db_password(self):
        """Generate a secure database password"""
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()[:43]
        
    def _get_config_file(self):
        """Get path to configuration file"""
        home_dir = os.path.expanduser("~")
        config_dir = os.path.join(home_dir, ".pypwd")
        os.makedirs(config_dir, exist_ok=True)
        return os.path.join(config_dir, "db_config.json")
        
    def _save_db_config(self):
        """Save database configuration securely"""
        config = {
            'host': self.db_host,
            'port': self.db_port,
            'database': self.db_name,
            'user': self.db_user,
            'password': self.db_password
        }
        
        config_file = self._get_config_file()
        with open(config_file, 'w') as f:
            json.dump(config, f)
        
        # Set restrictive permissions
        os.chmod(config_file, 0o600)
        
    def _load_db_config(self):
        """Load database configuration"""
        config_file = self._get_config_file()
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    self.db_host = config['host']
                    self.db_port = config['port']
                    self.db_name = config['database']
                    self.db_user = config['user']
                    self.db_password = config['password']
                    return True
            except (json.JSONDecodeError, KeyError):
                pass
        return False
        
    def _setup_database(self):
        """Setup database and user automatically"""
        # Try to load existing config first
        if self._load_db_config():
            return
            
        print("Setting up PyPWD database for first time...")
        print("This will create a secure database and user for PyPWD.")
        
        choice = input("\nSetup options:\n1. Automatic setup (requires MySQL root password)\n2. Manual setup (show commands to run)\nChoose (1/2): ").strip()
        
        if choice == "2":
            print(f"\nPlease run these commands in MySQL as root:")
            print(f"  CREATE DATABASE {self.db_name};")
            print(f"  CREATE USER '{self.db_user}'@'localhost' IDENTIFIED BY '{self.db_password}';")
            print(f"  GRANT ALL PRIVILEGES ON {self.db_name}.* TO '{self.db_user}'@'localhost';")
            print(f"  FLUSH PRIVILEGES;")
            
            self._save_db_config()
            print(f"\nConfiguration saved to: {self._get_config_file()}")
            print("\nAfter running the commands, restart PyPWD.")
            sys.exit(0)
        
        # Get MySQL root credentials for automatic setup
        root_password = getpass.getpass("Enter MySQL root password: ")
        
        try:
            # Connect as root to create database and user
            root_connection = mysql.connector.connect(
                host=self.db_host,
                port=self.db_port,
                user='root',
                password=root_password
            )
            
            cursor = root_connection.cursor()
            
            # Create database
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.db_name}")
            
            # Create user with generated password
            cursor.execute(f"CREATE USER IF NOT EXISTS '{self.db_user}'@'localhost' IDENTIFIED BY '{self.db_password}'")
            cursor.execute(f"GRANT ALL PRIVILEGES ON {self.db_name}.* TO '{self.db_user}'@'localhost'")
            cursor.execute("FLUSH PRIVILEGES")
            
            cursor.close()
            root_connection.close()
            
            # Save configuration for future use
            self._save_db_config()
            
            print("Database setup completed successfully!")
            
        except Error as e:
            print(f"Database setup failed: {e}")
            print("\nAlternative: If you don't have MySQL root access,")
            print("please create the database and user manually:")
            print(f"  CREATE DATABASE {self.db_name};")
            print(f"  CREATE USER '{self.db_user}'@'localhost' IDENTIFIED BY '{self.db_password}';")
            print(f"  GRANT ALL PRIVILEGES ON {self.db_name}.* TO '{self.db_user}'@'localhost';")
            print(f"  FLUSH PRIVILEGES;")
            print(f"\nDatabase password: {self.db_password}")
            
            # Save config anyway for manual setup
            self._save_db_config()
            print(f"\nConfiguration saved to: {self._get_config_file()}")
            sys.exit(1)
            
    def _connect_db(self):
        """Establish database connection"""
        try:
            if self.connection is None or not self.connection.is_connected():
                self.connection = mysql.connector.connect(
                    host=self.db_host,
                    port=self.db_port,
                    user=self.db_user,
                    password=self.db_password,
                    database=self.db_name
                )
                self._create_tables()
            return True
        except Error as e:
            print(f"Database connection error: {e}")
            return False
            
    def _create_tables(self):
        """Create necessary database tables"""
        cursor = self.connection.cursor()
        
        # Users table to store master password hashes and salts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        ''')
        
        # Passwords table to store encrypted password entries
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                service_name TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password BLOB NOT NULL,
                encrypted_notes BLOB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        self.connection.commit()
        cursor.close()
        
    def _disconnect_db(self):
        """Close database connection"""
        if self.connection and self.connection.is_connected():
            self.connection.close()
        
    def _validate_password_strength(self, password):
        """Validate password meets minimum security requirements"""
        if len(password) < 10:
            return False, "Password must be at least 10 characters long"
        return True, "Password meets requirements"
        
    def _check_rate_limit(self):
        """Check if user is rate limited due to failed attempts"""
        current_time = time.time()
        if self.failed_attempts >= self.max_attempts:
            time_since_last = current_time - self.last_attempt_time
            if time_since_last < self.lockout_duration:
                remaining = int(self.lockout_duration - time_since_last)
                print(f"Too many failed attempts. Please wait {remaining} seconds.")
                return False
            else:
                # Reset after lockout period
                self.failed_attempts = 0
        return True
        
    def _record_failed_attempt(self):
        """Record a failed login attempt"""
        self.failed_attempts += 1
        self.last_attempt_time = time.time()
        
    def _generate_salt(self):
        """Generate a cryptographically secure random salt"""
        return secrets.token_bytes(32)
        
    def _hash_password(self, password, salt):
        """Hash password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,  # Longer hash for password storage
            salt=salt,
            iterations=100000,
        )
        return base64.b64encode(kdf.derive(password.encode())).decode()
        
    def _derive_key(self, password):
        if self.salt is None:
            raise ValueError("Salt not initialized")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
        
    def _encrypt_data(self, data, password):
        key = self._derive_key(password)
        f = Fernet(key)
        encrypted_data = f.encrypt(data.encode())
        return encrypted_data
        
    def _decrypt_data(self, encrypted_data, password):
        try:
            key = self._derive_key(password)
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_data)
            return decrypted_data.decode()
        except (InvalidToken, ValueError, UnicodeDecodeError) as e:
            return None
            
    def _set_file_permissions(self, filepath):
        """Set restrictive file permissions (owner read/write only)"""
        try:
            os.chmod(filepath, 0o600)
        except OSError:
            print("Warning: Could not set restrictive file permissions")
            
    def create_new_user(self, username):
        """Create a new user account"""
        if not self._connect_db():
            return False
            
        print("Creating new password manager account...")
        print("Password requirements:")
        print("- At least 10 characters long")
        
        while True:
            master_password = getpass.getpass("Set master password: ")
            is_valid, message = self._validate_password_strength(master_password)
            if not is_valid:
                print(f"Error: {message}")
                continue
            break
            
        confirm_password = getpass.getpass("Confirm master password: ")
        
        if master_password != confirm_password:
            print("Passwords don't match!")
            return False
            
        # Generate unique salt for this user
        self.salt = self._generate_salt()
        
        # Create password hash
        password_hash = self._hash_password(master_password, self.salt)
        
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                INSERT INTO users (username, password_hash, salt) 
                VALUES (%s, %s, %s)
            ''', (username, password_hash, self.salt))
            self.connection.commit()
            self.user_id = cursor.lastrowid
            cursor.close()
            
            print(f"User account '{username}' created successfully!")
            return True
        except Error as e:
            if "Duplicate entry" in str(e):
                print(f"User '{username}' already exists!")
            else:
                print(f"Error creating user: {e}")
            return False
        
    def authenticate_user(self, username, master_password):
        """Authenticate user and load their data"""
        if not self._connect_db():
            return None
            
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT id, password_hash, salt FROM users WHERE username = %s
            ''', (username,))
            result = cursor.fetchone()
            cursor.close()
            
            if not result:
                return None
                
            user_id, stored_hash, salt = result
            self.salt = salt
            
            # Verify password
            computed_hash = self._hash_password(master_password, salt)
            if computed_hash == stored_hash:
                self.user_id = user_id
                return self.load_user_passwords(master_password)
            return None
            
        except Error as e:
            print(f"Authentication error: {e}")
            return None
            
    def load_user_passwords(self, master_password):
        """Load user's passwords from database"""
        if not self.user_id:
            return None
            
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT service_name, username, encrypted_password, encrypted_notes,
                       created_at, modified_at 
                FROM passwords WHERE user_id = %s
            ''', (self.user_id,))
            results = cursor.fetchall()
            cursor.close()
            
            passwords = []
            for row in results:
                service, username, enc_password, enc_notes, created, modified = row
                
                # Decrypt password and notes
                password = self._decrypt_data(enc_password, master_password)
                notes = ""
                if enc_notes:
                    notes = self._decrypt_data(enc_notes, master_password) or ""
                
                passwords.append({
                    "service": service,
                    "username": username, 
                    "password": password,
                    "notes": notes,
                    "created": created.isoformat() if created else "",
                    "modified": modified.isoformat() if modified else ""
                })
                
            return {"passwords": passwords}
            
        except Error as e:
            print(f"Error loading passwords: {e}")
            return None
            
    def add_password(self, data, master_password):
        print("\nAdd new password entry:")
        service = input("Service/Website: ").strip()
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")
        
        if not service or not username or not password:
            print("All fields are required!")
            return data
            
        # Encrypt password and notes
        encrypted_password = self._encrypt_data(password, master_password)
        encrypted_notes = self._encrypt_data("", master_password)  # Empty notes initially
        
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                INSERT INTO passwords (user_id, service_name, username, encrypted_password, encrypted_notes)
                VALUES (%s, %s, %s, %s, %s)
            ''', (self.user_id, service, username, encrypted_password, encrypted_notes))
            self.connection.commit()
            cursor.close()
            
            print("Password saved successfully!")
            
            # Reload data to include new entry
            return self.load_user_passwords(master_password)
            
        except Error as e:
            print(f"Error saving password: {e}")
            return data
        
        
    def _interactive_select(self, stdscr, items, title="Select an item"):
        """Interactive selection using arrow keys"""
        curses.curs_set(0)  # Hide cursor
        stdscr.clear()
        
        current_row = 0
        max_row = len(items) - 1
        
        while True:
            stdscr.clear()
            height, width = stdscr.getmaxyx()
            
            # Display title
            title_x = max(0, (width - len(title)) // 2)
            stdscr.addstr(0, title_x, title, curses.A_BOLD)
            stdscr.addstr(1, 0, "=" * min(width - 1, len(title)))
            
            # Display items
            start_row = 3
            for idx, item in enumerate(items):
                y = start_row + idx
                if y >= height - 2:  # Leave space for instructions
                    break
                    
                if idx == current_row:
                    stdscr.addstr(y, 2, f"> {item}", curses.A_REVERSE)
                else:
                    stdscr.addstr(y, 4, item)
            
            # Display instructions
            instructions = "↑↓: Navigate | Enter: Select | q: Back"
            stdscr.addstr(height - 2, 0, instructions[:width-1])
            
            stdscr.refresh()
            
            key = stdscr.getch()
            
            if key == curses.KEY_UP and current_row > 0:
                current_row -= 1
            elif key == curses.KEY_DOWN and current_row < max_row:
                current_row += 1
            elif key == ord('\n') or key == ord('\r'):
                return current_row
            elif key == ord('q'):
                return None
                
    def _password_detail_view(self, stdscr, entry, data, master_password):
        """Detailed view for a selected password entry"""
        while True:
            stdscr.clear()
            height, width = stdscr.getmaxyx()
            
            # Display entry details
            title = f"Password Details: {entry['service']}"
            title_x = max(0, (width - len(title)) // 2)
            stdscr.addstr(0, title_x, title, curses.A_BOLD)
            stdscr.addstr(1, 0, "=" * min(width - 1, len(title)))
            
            details = [
                f"Service: {entry['service']}",
                f"Username: {entry['username']}",
                f"Password: {'*' * len(entry['password'])}",
                f"Notes: {entry.get('notes', 'N/A')}",
                f"Created: {entry.get('created', 'N/A')}",
                f"Modified: {entry.get('modified', 'N/A')}"
            ]
            
            for i, detail in enumerate(details):
                stdscr.addstr(3 + i, 2, detail[:width-3])
            
            # Display options
            options = [
                "1. Show password in cleartext",
                "2. Export to file",
                "3. Add/Edit notes",
                "4. Edit entry",
                "5. Back to list"
            ]
            
            start_y = 3 + len(details) + 2
            stdscr.addstr(start_y, 0, "Options:", curses.A_BOLD)
            for i, option in enumerate(options):
                stdscr.addstr(start_y + 1 + i, 2, option)
            
            stdscr.addstr(height - 2, 0, "Enter option (1-5): ")
            stdscr.refresh()
            
            # Get user input
            curses.echo()
            choice = stdscr.getstr(height - 2, 19, 1).decode('utf-8')
            curses.noecho()
            
            if choice == '1':
                self._show_password_cleartext(stdscr, entry)
            elif choice == '2':
                self._export_password_to_file(stdscr, entry)
            elif choice == '3':
                self._edit_notes(stdscr, entry, data, master_password)
            elif choice == '4':
                self._edit_entry_interactive(stdscr, entry, data, master_password)
            elif choice == '5':
                break
                
    def _show_password_cleartext(self, stdscr, entry):
        """Display password in cleartext with warning"""
        stdscr.clear()
        height, width = stdscr.getmaxyx()
        
        warning = "⚠️  PASSWORD VISIBLE ON SCREEN  ⚠️"
        warning_x = max(0, (width - len(warning)) // 2)
        stdscr.addstr(1, warning_x, warning, curses.A_BOLD | curses.A_BLINK)
        
        stdscr.addstr(3, 2, f"Service: {entry['service']}")
        stdscr.addstr(4, 2, f"Username: {entry['username']}")
        stdscr.addstr(5, 2, f"Password: {entry['password']}", curses.A_BOLD)
        
        stdscr.addstr(height - 3, 0, "Press any key to hide password and return...")
        stdscr.refresh()
        stdscr.getch()
        
    def _export_password_to_file(self, stdscr, entry):
        """Export single password entry to text file"""
        filename = f"{entry['service']}_password.txt"
        try:
            with open(filename, 'w') as f:
                f.write(f"Service: {entry['service']}\n")
                f.write(f"Username: {entry['username']}\n")
                f.write(f"Password: {entry['password']}\n")
                f.write(f"Notes: {entry.get('notes', '')}\n")
                f.write(f"Exported: {datetime.datetime.now().isoformat()}\n")
            
            stdscr.clear()
            stdscr.addstr(2, 2, f"Password exported to: {filename}")
            stdscr.addstr(4, 2, "Press any key to continue...")
            stdscr.refresh()
            stdscr.getch()
        except Exception as e:
            stdscr.clear()
            stdscr.addstr(2, 2, f"Error exporting: {str(e)}")
            stdscr.addstr(4, 2, "Press any key to continue...")
            stdscr.refresh()
            stdscr.getch()
            
    def _edit_notes(self, stdscr, entry, data, master_password):
        """Edit notes for an entry"""
        stdscr.clear()
        height, width = stdscr.getmaxyx()
        
        stdscr.addstr(1, 2, f"Edit notes for: {entry['service']}", curses.A_BOLD)
        stdscr.addstr(3, 2, f"Current notes: {entry.get('notes', '')}")
        stdscr.addstr(5, 2, "New notes (leave blank to keep current):")
        
        curses.echo()
        curses.curs_set(1)
        new_notes = stdscr.getstr(6, 2, width - 4).decode('utf-8')
        curses.noecho()
        curses.curs_set(0)
        
        if new_notes.strip():
            # Update in database
            encrypted_notes = self._encrypt_data(new_notes.strip(), master_password)
            try:
                cursor = self.connection.cursor()
                cursor.execute('''
                    UPDATE passwords SET encrypted_notes = %s, modified_at = CURRENT_TIMESTAMP
                    WHERE user_id = %s AND service_name = %s AND username = %s
                ''', (encrypted_notes, self.user_id, entry['service'], entry['username']))
                self.connection.commit()
                cursor.close()
                
                entry['notes'] = new_notes.strip()
                entry['modified'] = datetime.datetime.now().isoformat()
                stdscr.addstr(8, 2, "Notes updated successfully!")
            except Error as e:
                stdscr.addstr(8, 2, f"Error updating notes: {e}")
        else:
            stdscr.addstr(8, 2, "Notes unchanged.")
            
        stdscr.addstr(9, 2, "Press any key to continue...")
        stdscr.refresh()
        stdscr.getch()
        
    def _edit_entry_interactive(self, stdscr, entry, data, master_password):
        """Interactive entry editing"""
        stdscr.clear()
        height, width = stdscr.getmaxyx()
        
        stdscr.addstr(1, 2, f"Edit entry: {entry['service']}", curses.A_BOLD)
        stdscr.addstr(2, 2, "Leave fields blank to keep current values")
        
        # Edit service
        stdscr.addstr(4, 2, f"Service [{entry['service']}]: ")
        curses.echo()
        curses.curs_set(1)
        new_service = stdscr.getstr(4, 4 + len(f"Service [{entry['service']}]: "), width - 6).decode('utf-8')
        
        # Edit username  
        stdscr.addstr(5, 2, f"Username [{entry['username']}]: ")
        new_username = stdscr.getstr(5, 4 + len(f"Username [{entry['username']}]: "), width - 6).decode('utf-8')
        
        # Edit password
        stdscr.addstr(6, 2, "New password (leave blank to keep current): ")
        curses.noecho()
        new_password = stdscr.getstr(6, 4 + len("New password (leave blank to keep current): "), width - 6).decode('utf-8')
        curses.echo()
        curses.curs_set(0)
        
        # Update in database
        try:
            cursor = self.connection.cursor()
            
            # Build update query dynamically based on what changed
            updates = []
            params = []
            
            if new_service.strip():
                updates.append("service_name = %s")
                params.append(new_service.strip())
                entry['service'] = new_service.strip()
                
            if new_username.strip():
                updates.append("username = %s") 
                params.append(new_username.strip())
                entry['username'] = new_username.strip()
                
            if new_password.strip():
                encrypted_password = self._encrypt_data(new_password.strip(), master_password)
                updates.append("encrypted_password = %s")
                params.append(encrypted_password)
                entry['password'] = new_password.strip()
            
            if updates:
                updates.append("modified_at = CURRENT_TIMESTAMP")
                params.extend([self.user_id, entry['service'], entry['username']])
                
                query = f"UPDATE passwords SET {', '.join(updates)} WHERE user_id = %s AND service_name = %s AND username = %s"
                cursor.execute(query, params)
                self.connection.commit()
                
                entry['modified'] = datetime.datetime.now().isoformat()
                stdscr.addstr(8, 2, "Entry updated successfully!")
            else:
                stdscr.addstr(8, 2, "No changes made.")
                
            cursor.close()
            
        except Error as e:
            stdscr.addstr(8, 2, f"Error updating entry: {e}")
        
        stdscr.addstr(9, 2, "Press any key to continue...")
        stdscr.refresh()
        stdscr.getch()
        
    def interactive_list_passwords(self, data, master_password):
        """Interactive password listing with arrow key navigation"""
        if not data["passwords"]:
            print("\nNo passwords stored.")
            return
            
        def list_ui(stdscr):
            entries = data["passwords"]
            items = [f"{entry['service']} ({entry['username']})" for entry in entries]
            
            while True:
                selected_idx = self._interactive_select(stdscr, items, "Password List")
                if selected_idx is None:
                    break
                    
                selected_entry = entries[selected_idx]
                self._password_detail_view(stdscr, selected_entry, data, master_password)
                
        curses.wrapper(list_ui)
        
    def interactive_search_passwords(self, data, master_password):
        """Interactive password search with arrow key navigation"""
        if not data["passwords"]:
            print("\nNo passwords stored.")
            return
            
        query = input("\nEnter search term (service/username): ").strip().lower()
        if not query:
            return
            
        matches = []
        for entry in data["passwords"]:
            if (query in entry["service"].lower() or 
                query in entry["username"].lower()):
                matches.append(entry)
                
        if not matches:
            print("No matches found.")
            return
            
        def search_ui(stdscr):
            items = [f"{entry['service']} ({entry['username']})" for entry in matches]
            
            while True:
                selected_idx = self._interactive_select(stdscr, items, f"Search Results: '{query}'")
                if selected_idx is None:
                    break
                    
                selected_entry = matches[selected_idx]
                self._password_detail_view(stdscr, selected_entry, data, master_password)
                
        curses.wrapper(search_ui)
            
    def run(self):
        print("PyPWD - Secure Password Manager")
        print("=" * 35)
        
        if not self._connect_db():
            print("Failed to connect to database. Please check your configuration.")
            return
            
        # Get username
        username = input("Username: ").strip()
        if not username:
            print("Username is required.")
            return
            
        # Check if user exists
        cursor = self.connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", (username,))
        user_exists = cursor.fetchone()[0] > 0
        cursor.close()
        
        if not user_exists:
            if input(f"User '{username}' not found. Create new account? (y/n): ").lower() == 'y':
                if not self.create_new_user(username):
                    return
            else:
                return
                
        # Rate limiting check
        if not self._check_rate_limit():
            return
            
        master_password = getpass.getpass("Enter master password: ")
        data = self.authenticate_user(username, master_password)
        
        if data is None:
            print("Invalid master password!")
            self._record_failed_attempt()
            return
            
        # Reset failed attempts on successful login
        self.failed_attempts = 0
        print("Password manager loaded successfully!")
        
        while True:
            print("\nOptions:")
            print("1. Add password")
            print("2. List passwords") 
            print("3. Search passwords")
            print("4. Exit")
            
            choice = input("\nSelect option (1-4): ").strip()
            
            if choice == '1':
                data = self.add_password(data, master_password)
            elif choice == '2':
                self.interactive_list_passwords(data, master_password)
            elif choice == '3':
                self.interactive_search_passwords(data, master_password)
            elif choice == '4':
                print("Goodbye!")
                break
            else:
                print("Invalid option!")

def main():
    try:
        pm = PasswordManager()
        pm.run()
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
    finally:
        try:
            pm._disconnect_db()
        except:
            pass

if __name__ == "__main__":
    main()