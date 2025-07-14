#!/usr/bin/env python3

import json
import os
import sys
import getpass
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class PasswordManager:
    def __init__(self, filename="passwords.enc"):
        self.filename = filename
        self.salt = b'salt1234567890ab'  # In production, use random salt per file
        
    def _derive_key(self, password):
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
        except Exception:
            return None
            
    def create_new_file(self):
        print("Creating new password manager file...")
        master_password = getpass.getpass("Set master password: ")
        confirm_password = getpass.getpass("Confirm master password: ")
        
        if master_password != confirm_password:
            print("Passwords don't match!")
            return False
            
        initial_data = {"passwords": []}
        encrypted_data = self._encrypt_data(json.dumps(initial_data), master_password)
        
        with open(self.filename, 'wb') as f:
            f.write(encrypted_data)
            
        print(f"Password file '{self.filename}' created successfully!")
        return True
        
    def load_passwords(self, master_password):
        if not os.path.exists(self.filename):
            return None
            
        with open(self.filename, 'rb') as f:
            encrypted_data = f.read()
            
        decrypted_data = self._decrypt_data(encrypted_data, master_password)
        if decrypted_data is None:
            return None
            
        try:
            return json.loads(decrypted_data)
        except json.JSONDecodeError:
            return None
            
    def save_passwords(self, data, master_password):
        encrypted_data = self._encrypt_data(json.dumps(data, indent=2), master_password)
        with open(self.filename, 'wb') as f:
            f.write(encrypted_data)
            
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
            print(f"   Password: {entry['password']}")
            print()
            
    def run(self):
        if not os.path.exists(self.filename):
            print(f"Password file '{self.filename}' not found.")
            if input("Create new password file? (y/n): ").lower() == 'y':
                if not self.create_new_file():
                    return
            else:
                return
                
        master_password = getpass.getpass("Enter master password: ")
        data = self.load_passwords(master_password)
        
        if data is None:
            print("Invalid master password or corrupted file!")
            return
            
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
                self.list_passwords(data)
            elif choice == '3':
                self.search_passwords(data)
            elif choice == '4':
                print("Goodbye!")
                break
            else:
                print("Invalid option!")

def main():
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = "passwords.enc"
        
    pm = PasswordManager(filename)
    pm.run()

if __name__ == "__main__":
    main()