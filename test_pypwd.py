#!/usr/bin/env python3

import unittest
import tempfile
import os
import json
import base64
import time
from unittest.mock import patch, MagicMock
from pypwd import PasswordManager

class TestPasswordManager(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_filename = "test_passwords.enc"
        # Change to temp directory for tests
        self.original_cwd = os.getcwd()
        os.chdir(self.temp_dir)
        self.pm = PasswordManager(self.test_filename)
        self.test_password = "TestPass123!"
        self.weak_password = "weak"
        
    def tearDown(self):
        """Clean up test files"""
        os.chdir(self.original_cwd)
        if os.path.exists(os.path.join(self.temp_dir, self.test_filename)):
            os.remove(os.path.join(self.temp_dir, self.test_filename))
        try:
            os.rmdir(self.temp_dir)
        except OSError:
            pass

class TestFilenameValidation(TestPasswordManager):
    """Test filename validation and path traversal protection"""
    
    def test_valid_filename(self):
        """Test valid filename is accepted"""
        pm = PasswordManager("valid_file.enc")
        self.assertEqual(pm.filename, "valid_file.enc")
        
    def test_filename_without_extension(self):
        """Test filename without .enc extension gets it added"""
        pm = PasswordManager("test_file")
        self.assertEqual(pm.filename, "test_file.enc")
        
    def test_path_traversal_protection(self):
        """Test path traversal attempts are blocked"""
        pm = PasswordManager("../../../etc/passwd")
        self.assertEqual(pm.filename, "passwd.enc")
        
    def test_invalid_characters_blocked(self):
        """Test invalid characters in filename are blocked"""
        with self.assertRaises(ValueError):
            PasswordManager("file|with<invalid>chars.enc")
            
    def test_empty_filename_blocked(self):
        """Test empty filename is blocked"""
        with self.assertRaises(ValueError):
            PasswordManager("")

class TestPasswordStrengthValidation(TestPasswordManager):
    """Test password strength validation"""
    
    def test_valid_strong_password(self):
        """Test strong password passes validation"""
        is_valid, message = self.pm._validate_password_strength("StrongPass123!")
        self.assertTrue(is_valid)
        self.assertEqual(message, "Password meets requirements")
        
    def test_too_short_password(self):
        """Test password too short fails validation"""
        is_valid, message = self.pm._validate_password_strength("Short1!")
        self.assertFalse(is_valid)
        self.assertIn("at least 8 characters", message)
        
    def test_no_uppercase_password(self):
        """Test password without uppercase fails validation"""
        is_valid, message = self.pm._validate_password_strength("lowercase123!")
        self.assertFalse(is_valid)
        self.assertIn("uppercase letter", message)
        
    def test_no_lowercase_password(self):
        """Test password without lowercase fails validation"""
        is_valid, message = self.pm._validate_password_strength("UPPERCASE123!")
        self.assertFalse(is_valid)
        self.assertIn("lowercase letter", message)
        
    def test_no_number_password(self):
        """Test password without numbers fails validation"""
        is_valid, message = self.pm._validate_password_strength("NoNumbers!")
        self.assertFalse(is_valid)
        self.assertIn("number", message)
        
    def test_no_special_char_password(self):
        """Test password without special characters fails validation"""
        is_valid, message = self.pm._validate_password_strength("NoSpecial123")
        self.assertFalse(is_valid)
        self.assertIn("special character", message)

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

class TestFileOperations(TestPasswordManager):
    """Test file creation, loading, and saving"""
    
    @patch('getpass.getpass')
    def test_create_new_file(self, mock_getpass):
        """Test creating a new password file"""
        mock_getpass.side_effect = [self.test_password, self.test_password]
        
        result = self.pm.create_new_file()
        
        self.assertTrue(result)
        self.assertTrue(os.path.exists(self.test_filename))
        
        # Check file permissions (should be 600)
        file_stat = os.stat(self.test_filename)
        file_perms = oct(file_stat.st_mode)[-3:]
        self.assertEqual(file_perms, "600")
        
    @patch('getpass.getpass')
    def test_create_file_password_mismatch(self, mock_getpass):
        """Test file creation fails when passwords don't match"""
        mock_getpass.side_effect = [self.test_password, "different_password"]
        
        result = self.pm.create_new_file()
        
        self.assertFalse(result)
        self.assertFalse(os.path.exists(self.test_filename))
        
    @patch('getpass.getpass')
    def test_create_file_weak_password_rejected(self, mock_getpass):
        """Test file creation rejects weak passwords"""
        mock_getpass.side_effect = [self.weak_password, self.test_password, self.test_password]
        
        result = self.pm.create_new_file()
        
        self.assertTrue(result)
        
    @patch('getpass.getpass')
    def test_load_passwords_success(self, mock_getpass):
        """Test loading passwords from file"""
        mock_getpass.side_effect = [self.test_password, self.test_password]
        
        # Create file first
        self.pm.create_new_file()
        
        # Create a fresh instance to test loading (reset rate limiting)
        pm_fresh = PasswordManager(self.test_filename)
        data = pm_fresh.load_passwords(self.test_password)
        
        self.assertIsNotNone(data)
        self.assertIn('passwords', data)
        self.assertEqual(len(data['passwords']), 0)
        # Salt should be set in the PasswordManager instance
        self.assertIsNotNone(pm_fresh.salt)
        
    def test_load_passwords_wrong_password(self):
        """Test loading fails with wrong password"""
        # Create a file with test data
        self.pm.salt = self.pm._generate_salt()
        test_data = {
            "salt": base64.b64encode(self.pm.salt).decode(),
            "passwords": []
        }
        encrypted_data = self.pm._encrypt_data(json.dumps(test_data), self.test_password)
        
        with open(self.test_filename, 'wb') as f:
            f.write(encrypted_data)
            
        # Try to load with wrong password
        data = self.pm.load_passwords("wrong_password")
        
        self.assertIsNone(data)
        
    def test_load_nonexistent_file(self):
        """Test loading non-existent file returns None"""
        data = self.pm.load_passwords(self.test_password)
        self.assertIsNone(data)

class TestPasswordCRUD(TestPasswordManager):
    """Test password CRUD operations"""
    
    def setUp(self):
        super().setUp()
        # Create a test file with sample data
        self.pm.salt = self.pm._generate_salt()
        self.test_data = {
            "salt": base64.b64encode(self.pm.salt).decode(),
            "passwords": [
                {
                    "service": "Gmail",
                    "username": "test@gmail.com",
                    "password": "gmail_pass123"
                },
                {
                    "service": "GitHub",
                    "username": "testuser",
                    "password": "github_pass456"
                }
            ]
        }
        
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
        
    @patch('builtins.input')
    @patch('getpass.getpass')
    def test_add_password_empty_fields(self, mock_getpass, mock_input):
        """Test adding password with empty fields is rejected"""
        mock_input.side_effect = ["", "username"]
        mock_getpass.return_value = "password"
        
        original_count = len(self.test_data['passwords'])
        data = self.pm.add_password(self.test_data.copy(), self.test_password)
        
        self.assertEqual(len(data['passwords']), original_count)
        
    @patch('sys.stdout')
    def test_list_passwords(self, mock_stdout):
        """Test listing passwords"""
        self.pm.list_passwords(self.test_data)
        
        # Check that output was generated (passwords should be masked)
        mock_stdout.write.assert_called()
        
    def test_list_passwords_empty(self):
        """Test listing passwords when none exist"""
        empty_data = {"passwords": []}
        # Should not raise an exception
        self.pm.list_passwords(empty_data)
        
    @patch('builtins.input')
    def test_search_passwords_found(self, mock_input):
        """Test searching for passwords"""
        mock_input.side_effect = ["gmail", "y"]  # search term, show passwords
        
        # Capture output by patching print
        with patch('builtins.print') as mock_print:
            self.pm.search_passwords(self.test_data)
            
        # Check that Gmail entry was found and displayed
        calls = [str(call) for call in mock_print.call_args_list]
        output = " ".join(calls)
        self.assertIn("Gmail", output)
        self.assertIn("gmail_pass123", output)
        
    @patch('builtins.input')
    def test_search_passwords_hidden(self, mock_input):
        """Test searching with passwords hidden"""
        mock_input.side_effect = ["gmail", "n"]  # search term, hide passwords
        
        with patch('builtins.print') as mock_print:
            self.pm.search_passwords(self.test_data)
            
        calls = [str(call) for call in mock_print.call_args_list]
        output = " ".join(calls)
        self.assertIn("Gmail", output)
        self.assertNotIn("gmail_pass123", output)
        self.assertIn("*" * len("gmail_pass123"), output)
        
    @patch('builtins.input')
    @patch('getpass.getpass')
    def test_edit_password(self, mock_getpass, mock_input):
        """Test editing an existing password"""
        mock_input.side_effect = ["1", "Gmail Updated", "new@gmail.com"]
        mock_getpass.return_value = "new_password123"
        
        data = self.pm.edit_password(self.test_data.copy(), self.test_password)
        
        edited_entry = data['passwords'][0]
        self.assertEqual(edited_entry['service'], "Gmail Updated")
        self.assertEqual(edited_entry['username'], "new@gmail.com")
        self.assertEqual(edited_entry['password'], "new_password123")
        
    @patch('builtins.input')
    @patch('getpass.getpass')
    def test_edit_password_keep_existing(self, mock_getpass, mock_input):
        """Test editing password while keeping some existing values"""
        mock_input.side_effect = ["1", "", "new@gmail.com"]  # Keep service name
        mock_getpass.return_value = ""  # Keep existing password
        
        original_data = self.test_data.copy()
        data = self.pm.edit_password(original_data, self.test_password)
        
        edited_entry = data['passwords'][0]
        self.assertEqual(edited_entry['service'], "Gmail")  # Unchanged
        self.assertEqual(edited_entry['username'], "new@gmail.com")  # Changed
        self.assertEqual(edited_entry['password'], "gmail_pass123")  # Unchanged
        
    @patch('builtins.input')
    def test_edit_password_invalid_index(self, mock_input):
        """Test editing with invalid password index"""
        mock_input.return_value = "999"  # Invalid index
        
        original_data = self.test_data.copy()
        data = self.pm.edit_password(original_data, self.test_password)
        
        # Data should be unchanged
        self.assertEqual(data, original_data)

class TestBackwardCompatibility(TestPasswordManager):
    """Test backward compatibility with legacy files"""
    
    def test_load_legacy_file_format(self):
        """Test loading files created with old format (fixed salt)"""
        # Create a legacy format file (entire file is encrypted data, no salt prefix)
        legacy_salt = b'salt1234567890ab'
        temp_pm = PasswordManager(self.test_filename)
        temp_pm.salt = legacy_salt
        
        legacy_data = {"passwords": []}
        encrypted_data = temp_pm._encrypt_data(json.dumps(legacy_data), self.test_password)
        
        with open(self.test_filename, 'wb') as f:
            # Legacy format: write only encrypted data (no salt prefix)
            f.write(encrypted_data)
            
        # Reset pm to simulate fresh load
        pm_fresh = PasswordManager(self.test_filename)
        data = pm_fresh.load_passwords(self.test_password)
        
        self.assertIsNotNone(data)
        self.assertIn('passwords', data)
        # Should have loaded with legacy salt
        self.assertEqual(pm_fresh.salt, legacy_salt)

class TestIntegration(TestPasswordManager):
    """Integration tests"""
    
    @patch('builtins.input')
    @patch('getpass.getpass')
    def test_full_workflow(self, mock_getpass, mock_input):
        """Test complete workflow from file creation to password management"""
        # Mock inputs for file creation
        mock_getpass.side_effect = [
            self.test_password, self.test_password,  # Create file
            "facebook_pass"  # Add password
        ]
        mock_input.side_effect = [
            "Facebook", "user@fb.com",  # Service and username
        ]
        
        # Simulate the workflow
        self.pm.create_new_file()
        
        # Create fresh instance to test loading without rate limiting issues
        pm_fresh = PasswordManager(self.test_filename)
        data = pm_fresh.load_passwords(self.test_password)
        self.assertIsNotNone(data)
        
        # Add a password
        data = pm_fresh.add_password(data, self.test_password)
        self.assertEqual(len(data['passwords']), 1)
        
        # Verify password was saved by creating another fresh instance
        pm_verify = PasswordManager(self.test_filename)
        saved_data = pm_verify.load_passwords(self.test_password)
        self.assertEqual(len(saved_data['passwords']), 1)
        self.assertEqual(saved_data['passwords'][0]['service'], "Facebook")

def run_tests():
    """Run all tests and return results"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestFilenameValidation,
        TestPasswordStrengthValidation,
        TestEncryptionDecryption,
        TestRateLimiting,
        TestFileOperations,
        TestPasswordCRUD,
        TestBackwardCompatibility,
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