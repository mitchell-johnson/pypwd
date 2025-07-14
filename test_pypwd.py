#!/usr/bin/env python3

import unittest
import tempfile
import os
import json
import base64
import time
import sqlite3
from unittest.mock import patch, MagicMock
from pypwd import PasswordManager

class TestPasswordManager(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        # Mock the database path to use temp directory
        self.test_db_path = os.path.join(self.temp_dir, "test_pypwd.db")
        
        # Patch the _get_db_path method to return test path
        with patch.object(PasswordManager, '_get_db_path', return_value=self.test_db_path):
            self.pm = PasswordManager()
        
        self.test_password = "TestPassword123"
        self.weak_password = "short"
        
    def tearDown(self):
        """Clean up test files"""
        if hasattr(self.pm, 'connection') and self.pm.connection:
            self.pm.connection.close()
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        try:
            os.rmdir(self.temp_dir)
        except OSError:
            pass

class TestDatabaseSetup(TestPasswordManager):
    """Test database setup and connection"""
    
    def test_database_path_creation(self):
        """Test database path is created correctly"""
        self.assertTrue(os.path.exists(self.test_db_path))
        
    def test_database_tables_created(self):
        """Test that required tables are created"""
        cursor = self.pm.connection.cursor()
        
        # Check users table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        self.assertIsNotNone(cursor.fetchone())
        
        # Check passwords table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='passwords'")
        self.assertIsNotNone(cursor.fetchone())
        
        cursor.close()
        
    def test_database_file_permissions(self):
        """Test database file has correct permissions"""
        file_stat = os.stat(self.test_db_path)
        file_perms = oct(file_stat.st_mode)[-3:]
        self.assertEqual(file_perms, "600")

class TestPasswordStrengthValidation(TestPasswordManager):
    """Test password strength validation"""
    
    def test_valid_password(self):
        """Test valid password passes validation"""
        is_valid, message = self.pm._validate_password_strength("ValidPassword123")
        self.assertTrue(is_valid)
        self.assertEqual(message, "Password meets requirements")
        
    def test_too_short_password(self):
        """Test password too short fails validation"""
        is_valid, message = self.pm._validate_password_strength("Short")
        self.assertFalse(is_valid)
        self.assertIn("at least 10 characters", message)
        
    def test_minimum_length_password(self):
        """Test password with exactly 10 characters passes"""
        is_valid, message = self.pm._validate_password_strength("1234567890")
        self.assertTrue(is_valid)
        self.assertEqual(message, "Password meets requirements")
        
    def test_simple_long_password(self):
        """Test simple but long password passes validation"""
        is_valid, message = self.pm._validate_password_strength("thisisalongpassword")
        self.assertTrue(is_valid)
        self.assertEqual(message, "Password meets requirements")

class TestEncryptionDecryption(TestPasswordManager):
    """Test encryption and decryption functionality"""
    
    def test_salt_generation(self):
        """Test salt generation produces unique values"""
        salt1 = self.pm._generate_salt()
        salt2 = self.pm._generate_salt()
        self.assertNotEqual(salt1, salt2)
        self.assertEqual(len(salt1), 32)
        self.assertEqual(len(salt2), 32)
        
    def test_key_derivation_requires_salt(self):
        """Test key derivation fails without salt"""
        with self.assertRaises(ValueError):
            self.pm._derive_key("password")
            
    def test_encryption_decryption_roundtrip(self):
        """Test data can be encrypted and decrypted"""
        self.pm.salt = self.pm._generate_salt()
        test_data = "This is test data"
        
        encrypted = self.pm._encrypt_data(test_data, self.test_password)
        decrypted = self.pm._decrypt_data(encrypted, self.test_password)
        
        self.assertEqual(test_data, decrypted)
        
    def test_wrong_password_decryption_fails(self):
        """Test decryption fails with wrong password"""
        self.pm.salt = self.pm._generate_salt()
        test_data = "This is test data"
        
        encrypted = self.pm._encrypt_data(test_data, self.test_password)
        decrypted = self.pm._decrypt_data(encrypted, "wrong_password")
        
        self.assertIsNone(decrypted)

class TestRateLimiting(TestPasswordManager):
    """Test rate limiting functionality"""
    
    def test_initial_rate_limit_allows_access(self):
        """Test initial state allows access"""
        self.assertTrue(self.pm._check_rate_limit())
        
    def test_rate_limit_after_max_attempts(self):
        """Test rate limit kicks in after max failed attempts"""
        # Simulate max failed attempts
        for _ in range(self.pm.max_attempts):
            self.pm._record_failed_attempt()
            
        self.assertFalse(self.pm._check_rate_limit())
        
    def test_rate_limit_resets_after_lockout_period(self):
        """Test rate limit resets after lockout period"""
        # Simulate max failed attempts
        for _ in range(self.pm.max_attempts):
            self.pm._record_failed_attempt()
            
        # Set last attempt time to past the lockout duration
        self.pm.last_attempt_time = time.time() - (self.pm.lockout_duration + 1)
        
        self.assertTrue(self.pm._check_rate_limit())
        self.assertEqual(self.pm.failed_attempts, 0)

class TestUserManagement(TestPasswordManager):
    """Test user creation and authentication"""
    
    @patch('getpass.getpass')
    def test_create_new_user(self, mock_getpass):
        """Test creating a new user account"""
        mock_getpass.side_effect = [self.test_password, self.test_password]
        
        result = self.pm.create_new_user("testuser")
        
        self.assertTrue(result)
        self.assertEqual(self.pm.user_id, 1)  # First user should have ID 1
        
    @patch('getpass.getpass')
    def test_create_user_password_mismatch(self, mock_getpass):
        """Test user creation fails when passwords don't match"""
        mock_getpass.side_effect = [self.test_password, "different_password"]
        
        result = self.pm.create_new_user("testuser")
        
        self.assertFalse(result)
        self.assertIsNone(self.pm.user_id)
        
    @patch('getpass.getpass')
    def test_create_user_weak_password_rejected(self, mock_getpass):
        """Test user creation rejects weak passwords"""
        mock_getpass.side_effect = [self.weak_password, self.test_password, self.test_password]
        
        result = self.pm.create_new_user("testuser")
        
        self.assertTrue(result)
        
    def test_authenticate_user_success(self):
        """Test successful user authentication"""
        # Create user first
        with patch('getpass.getpass', side_effect=[self.test_password, self.test_password]):
            self.pm.create_new_user("testuser")
        
        # Test authentication
        data = self.pm.authenticate_user("testuser", self.test_password)
        
        self.assertIsNotNone(data)
        self.assertIn('passwords', data)
        self.assertEqual(len(data['passwords']), 0)
        
    def test_authenticate_user_wrong_password(self):
        """Test authentication fails with wrong password"""
        # Create user first
        with patch('getpass.getpass', side_effect=[self.test_password, self.test_password]):
            self.pm.create_new_user("testuser")
            
        # Try to authenticate with wrong password
        data = self.pm.authenticate_user("testuser", "wrong_password")
        
        self.assertIsNone(data)
        
    def test_authenticate_nonexistent_user(self):
        """Test authentication fails for non-existent user"""
        data = self.pm.authenticate_user("nonexistent", self.test_password)
        self.assertIsNone(data)

class TestPasswordCRUD(TestPasswordManager):
    """Test password CRUD operations"""
    
    def setUp(self):
        super().setUp()
        # Create a test user and authenticate
        with patch('getpass.getpass', side_effect=[self.test_password, self.test_password]):
            self.pm.create_new_user("testuser")
        
        # Add some test data to the database
        self.pm.salt = self.pm._generate_salt()
        
        # Add test passwords directly to database
        cursor = self.pm.connection.cursor()
        
        # Add Gmail entry
        encrypted_password1 = self.pm._encrypt_data("gmail_pass123", self.test_password)
        encrypted_notes1 = self.pm._encrypt_data("", self.test_password)
        cursor.execute('''
            INSERT INTO passwords (user_id, service_name, username, encrypted_password, encrypted_notes)
            VALUES (?, ?, ?, ?, ?)
        ''', (self.pm.user_id, "Gmail", "test@gmail.com", encrypted_password1, encrypted_notes1))
        
        # Add GitHub entry
        encrypted_password2 = self.pm._encrypt_data("github_pass456", self.test_password)
        encrypted_notes2 = self.pm._encrypt_data("Work account", self.test_password)
        cursor.execute('''
            INSERT INTO passwords (user_id, service_name, username, encrypted_password, encrypted_notes)
            VALUES (?, ?, ?, ?, ?)
        ''', (self.pm.user_id, "GitHub", "testuser", encrypted_password2, encrypted_notes2))
        
        self.pm.connection.commit()
        cursor.close()
        
        # Load the test data
        self.test_data = self.pm.load_user_passwords(self.test_password)
        
    @patch('builtins.input')
    @patch('getpass.getpass')
    def test_add_password(self, mock_getpass, mock_input):
        """Test adding a new password"""
        mock_input.return_value = "Facebook"
        mock_input.side_effect = ["Facebook", "user@facebook.com"]
        mock_getpass.return_value = "facebook_pass789"
        
        data = self.pm.add_password(self.test_data.copy(), self.test_password)
        
        self.assertEqual(len(data['passwords']), 3)
        new_entry = data['passwords'][-1]
        self.assertEqual(new_entry['service'], "Facebook")
        self.assertEqual(new_entry['username'], "user@facebook.com")
        self.assertEqual(new_entry['password'], "facebook_pass789")
        # Check new fields are present
        self.assertIn('notes', new_entry)
        self.assertIn('created', new_entry) 
        self.assertIn('modified', new_entry)
        
    @patch('builtins.input')
    @patch('getpass.getpass')
    def test_add_password_empty_fields(self, mock_getpass, mock_input):
        """Test adding password with empty fields is rejected"""
        mock_input.side_effect = ["", "username"]
        mock_getpass.return_value = "password"
        
        original_count = len(self.test_data['passwords'])
        data = self.pm.add_password(self.test_data.copy(), self.test_password)
        
        self.assertEqual(len(data['passwords']), original_count)
        
    def test_load_user_passwords(self):
        """Test loading user passwords from database"""
        data = self.pm.load_user_passwords(self.test_password)
        
        self.assertIsNotNone(data)
        self.assertIn('passwords', data)
        self.assertEqual(len(data['passwords']), 2)
        
        # Check first password entry
        gmail_entry = next(p for p in data['passwords'] if p['service'] == 'Gmail')
        self.assertEqual(gmail_entry['username'], "test@gmail.com")
        self.assertEqual(gmail_entry['password'], "gmail_pass123")
        
    def test_interactive_ui_methods_exist(self):
        """Test that interactive UI methods exist"""
        # Test that interactive methods exist (even if we can't easily test their UI)
        self.assertTrue(hasattr(self.pm, 'interactive_list_passwords'))
        self.assertTrue(hasattr(self.pm, 'interactive_search_passwords'))
        self.assertTrue(hasattr(self.pm, '_interactive_select'))
        self.assertTrue(hasattr(self.pm, '_password_detail_view'))
        
    def test_database_password_encryption(self):
        """Test that passwords are properly encrypted in database"""
        cursor = self.pm.connection.cursor()
        cursor.execute("SELECT encrypted_password FROM passwords WHERE service_name = ?", ("Gmail",))
        encrypted_data = cursor.fetchone()[0]
        cursor.close()
        
        # Encrypted data should be different from plaintext
        self.assertNotEqual(encrypted_data, b"gmail_pass123")
        
        # Should be able to decrypt with correct password
        decrypted = self.pm._decrypt_data(encrypted_data, self.test_password)
        self.assertEqual(decrypted, "gmail_pass123")

class TestIntegration(TestPasswordManager):
    """Integration tests"""
    
    @patch('builtins.input')
    @patch('getpass.getpass')
    def test_full_workflow(self, mock_getpass, mock_input):
        """Test complete workflow from user creation to password management"""
        # Mock inputs for user creation and password addition
        mock_getpass.side_effect = [
            self.test_password, self.test_password,  # Create user
            "facebook_pass"  # Add password
        ]
        mock_input.side_effect = [
            "Facebook", "user@fb.com",  # Service and username
        ]
        
        # Simulate the workflow
        self.pm.create_new_user("integrationtest")
        
        # Authenticate user
        data = self.pm.authenticate_user("integrationtest", self.test_password)
        self.assertIsNotNone(data)
        
        # Add a password
        data = self.pm.add_password(data, self.test_password)
        self.assertEqual(len(data['passwords']), 1)
        
        # Verify password was saved by loading again
        saved_data = self.pm.load_user_passwords(self.test_password)
        self.assertEqual(len(saved_data['passwords']), 1)
        self.assertEqual(saved_data['passwords'][0]['service'], "Facebook")

def run_tests():
    """Run all tests and return results"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestDatabaseSetup,
        TestPasswordStrengthValidation,
        TestEncryptionDecryption,
        TestRateLimiting,
        TestUserManagement,
        TestPasswordCRUD,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result

if __name__ == "__main__":
    print("Running comprehensive test suite for PyPWD...")
    print("=" * 60)
    
    result = run_tests()
    
    print("\n" + "=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\nFAILURES:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")
    
    if result.errors:
        print("\nERRORS:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")
    
    if result.wasSuccessful():
        print("\n✅ All tests passed!")
    else:
        print(f"\n❌ {len(result.failures + result.errors)} test(s) failed")
        exit(1)