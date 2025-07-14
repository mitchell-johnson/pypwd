#!/usr/bin/env python3

import json
import os
import sys
import getpass
import secrets
import time
import re
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class PasswordManager:
    def __init__(self, filename="passwords.enc"):
        self.filename = self._validate_filename(filename)
        self.salt = None
        self.failed_attempts = 0
        self.last_attempt_time = 0
        self.max_attempts = 3
        self.lockout_duration = 30  # seconds
        
    def _validate_filename(self, filename):
        """Validate filename to prevent path traversal attacks"""
        if not filename:
            raise ValueError("Filename cannot be empty")
        
        # Remove any path components and keep only the filename
        filename = os.path.basename(filename)
        
        # Check for valid characters (alphanumeric, dots, underscores, hyphens)
        if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
            raise ValueError("Invalid characters in filename")
            
        # Ensure it has .enc extension
        if not filename.endswith('.enc'):
            filename += '.enc'
            
        return filename
        
    def _validate_password_strength(self, password):
        """Validate password meets minimum security requirements"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r'\d', password):
            return False, "Password must contain at least one number"
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
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
            
    def create_new_file(self):
        print("Creating new password manager file...")
        print("Password requirements:")
        print("- At least 8 characters long")
        print("- Contains uppercase and lowercase letters")
        print("- Contains at least one number")
        print("- Contains at least one special character")
        
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
            
        # Generate unique salt for this file
        self.salt = self._generate_salt()
        
        initial_data = {"passwords": []}
        encrypted_data = self._encrypt_data(json.dumps(initial_data), master_password)
        
        with open(self.filename, 'wb') as f:
            # Write salt first (32 bytes), then encrypted data
            f.write(self.salt)
            f.write(encrypted_data)
            
        self._set_file_permissions(self.filename)
        print(f"Password file '{self.filename}' created successfully!")
        return True
        
    def load_passwords(self, master_password):
        if not os.path.exists(self.filename):
            return None
            
        with open(self.filename, 'rb') as f:
            file_data = f.read()
            
        # Check if this is a new format file (starts with 32-byte salt)
        if len(file_data) >= 32:
            # Try new format: salt (32 bytes) + encrypted data
            potential_salt = file_data[:32]
            encrypted_data = file_data[32:]
            
            self.salt = potential_salt
            decrypted_data = self._decrypt_data(encrypted_data, master_password)
            
            if decrypted_data is not None:
                try:
                    data = json.loads(decrypted_data)
                    if 'passwords' in data:  # Valid new format
                        return data
                except json.JSONDecodeError:
                    pass
        
        # Fall back to legacy format (entire file is encrypted data with fixed salt)
        self.salt = b'salt1234567890ab'
        decrypted_data = self._decrypt_data(file_data, master_password)
        
        if decrypted_data is not None:
            try:
                data = json.loads(decrypted_data)
                if 'passwords' in data:  # Valid legacy format
                    return data
            except json.JSONDecodeError:
                pass
        
        return None
            
    def save_passwords(self, data, master_password):
        encrypted_data = self._encrypt_data(json.dumps(data, indent=2), master_password)
        with open(self.filename, 'wb') as f:
            # Write salt first (32 bytes), then encrypted data
            f.write(self.salt)
            f.write(encrypted_data)
        self._set_file_permissions(self.filename)
            
    def add_password(self, data, master_password):
        print("\nAdd new password entry:")
        service = input("Service/Website: ").strip()
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")
        
        if not service or not username or not password:
            print("All fields are required!")
            return data
            
        new_entry = {
            "service": service,
            "username": username,
            "password": password
        }
        
        data["passwords"].append(new_entry)
        self.save_passwords(data, master_password)
        print("Password saved successfully!")
        return data
        
    def list_passwords(self, data):
        if not data["passwords"]:
            print("\nNo passwords stored.")
            return
            
        print(f"\nStored passwords ({len(data['passwords'])} entries):")
        print("-" * 50)
        for i, entry in enumerate(data["passwords"], 1):
            print(f"{i}. {entry['service']}")
            print(f"   Username: {entry['username']}")
            print(f"   Password: {'*' * len(entry['password'])}")
            print()
            
    def search_passwords(self, data):
        if not data["passwords"]:
            print("\nNo passwords stored.")
            return
            
        query = input("\nEnter search term (service/username): ").strip().lower()
        if not query:
            return
            
        show_passwords = input("Show passwords in results? (y/n): ").lower() == 'y'
            
        matches = []
        for entry in data["passwords"]:
            if (query in entry["service"].lower() or 
                query in entry["username"].lower()):
                matches.append(entry)
                
        if not matches:
            print("No matches found.")
            return
            
        print(f"\nSearch results ({len(matches)} matches):")
        print("-" * 50)
        for i, entry in enumerate(matches, 1):
            print(f"{i}. {entry['service']}")
            print(f"   Username: {entry['username']}")
            if show_passwords:
                print(f"   Password: {entry['password']}")
            else:
                print(f"   Password: {'*' * len(entry['password'])}")
            print()
            
    def edit_password(self, data, master_password):
        if not data["passwords"]:
            print("\nNo passwords stored.")
            return data
            
        print(f"\nSelect entry to edit ({len(data['passwords'])} entries):")
        print("-" * 50)
        for i, entry in enumerate(data["passwords"], 1):
            print(f"{i}. {entry['service']} ({entry['username']})")
            
        try:
            choice = int(input("\nEnter entry number: ").strip())
            if choice < 1 or choice > len(data["passwords"]):
                print("Invalid entry number!")
                return data
        except ValueError:
            print("Invalid input!")
            return data
            
        entry_index = choice - 1
        entry = data["passwords"][entry_index]
        
        print(f"\nEditing: {entry['service']}")
        print("Leave blank to keep current value:")
        
        new_service = input(f"Service/Website [{entry['service']}]: ").strip()
        new_username = input(f"Username [{entry['username']}]: ").strip()
        new_password = getpass.getpass("New Password (leave blank to keep current): ")
        
        if new_service:
            entry["service"] = new_service
        if new_username:
            entry["username"] = new_username
        if new_password:
            entry["password"] = new_password
            
        data["passwords"][entry_index] = entry
        self.save_passwords(data, master_password)
        print("Password entry updated successfully!")
        return data
            
    def run(self):
        if not os.path.exists(self.filename):
            print(f"Password file '{self.filename}' not found.")
            if input("Create new password file? (y/n): ").lower() == 'y':
                if not self.create_new_file():
                    return
            else:
                return
                
        # Rate limiting check
        if not self._check_rate_limit():
            return
            
        master_password = getpass.getpass("Enter master password: ")
        data = self.load_passwords(master_password)
        
        if data is None:
            print("Invalid master password or corrupted file!")
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
            print("4. Edit password")
            print("5. Exit")
            
            choice = input("\nSelect option (1-5): ").strip()
            
            if choice == '1':
                data = self.add_password(data, master_password)
            elif choice == '2':
                self.list_passwords(data)
            elif choice == '3':
                self.search_passwords(data)
            elif choice == '4':
                data = self.edit_password(data, master_password)
            elif choice == '5':
                print("Goodbye!")
                break
            else:
                print("Invalid option!")

def main():
    try:
        if len(sys.argv) > 1:
            filename = sys.argv[1]
        else:
            filename = "passwords.enc"
            
        pm = PasswordManager(filename)
        pm.run()
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)

if __name__ == "__main__":
    main()