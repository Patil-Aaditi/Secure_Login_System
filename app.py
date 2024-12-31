import hashlib
import getpass
import os
import re
from cryptography.fernet import Fernet
from datetime import datetime, timedelta

class LoginSystem:
    def __init__(self):
        self.users = {}
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)

    def register(self, username, password, email):
        """Register a new user"""
        salt, hashed_password = self._hash_password(password)
        encrypted_email = self._encrypt_data(email)
        password_expiry = datetime.now() + timedelta(minutes=1)
        self.users[username] = (salt, hashed_password, encrypted_email, password_expiry)

    def login(self, username, password):
        """Login an existing user"""
        if username not in self.users:
            return False
        salt, hashed_password, _, password_expiry = self.users[username]
        if datetime.now() > password_expiry:
            print("Password has expired. Please reset your password.")
            return False
        new_hashed_password = self._hash_password_with_salt(password, salt)
        return new_hashed_password == hashed_password

    def reset_password(self, username, new_password):
        """Reset the password for a user"""
        if username not in self.users:
            print("User does not exist.")
            return False
        salt, _, encrypted_email, _ = self.users[username]
        new_salt, new_hashed_password = self._hash_password(new_password)
        password_expiry = datetime.now() + timedelta(minutes=1)
        self.users[username] = (new_salt, new_hashed_password, encrypted_email, password_expiry)
        print("Password reset successfully!")
        return True

    def _hash_password(self, password):
        """Hash a password using SHA-256"""
        salt = os.urandom(32)
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return salt, hashed_password

    def _hash_password_with_salt(self, password, salt):
        """Hash a password using SHA-256 and a given salt"""
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return hashed_password

    def _encrypt_data(self, data):
        """Encrypt sensitive data"""
        return self.cipher_suite.encrypt(data.encode('utf-8'))

    def _decrypt_data(self, encrypted_data):
        """Decrypt sensitive data"""
        return self.cipher_suite.decrypt(encrypted_data).decode('utf-8')

    def check_password_strength(self, password):
        """Check the strength of a password"""
        score = 0

        if len(password) >= 8:
            score += 1
        if re.search(r"[a-z]", password):
            score += 1
        if re.search(r"[A-Z]", password):
            score += 1
        if re.search(r"\d", password):
            score += 1
        if re.search(r"[!@#$%^&*]", password):
            score += 1

        if score <= 2:
            return "Weak"
        elif score <= 3:
            return "Moderate"
        elif score <= 4:
            return "Strong"
        else:
            return "Very Strong"

def get_valid_email():
    """Prompt the user to input a valid email address"""
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    while True:
        email = input("Enter your email: ")
        if re.match(email_regex, email):
            return email
        else:
            print("Invalid email address. Please try again.")

def get_strong_password():
    while True:
        password = getpass.getpass("Enter a password: ")
        strength = LoginSystem().check_password_strength(password)
        if strength == "Very Strong":
            return password
        else:
            print("Password is not strong enough. Please try again.")

def main():
    login_system = LoginSystem()
    logged_in = False

    if not logged_in:
        print("Welcome! Register Here.")
        username = input("Enter your username: ")
        email = get_valid_email()
        password = get_strong_password()
        login_system.register(username, password, email)
        print("User registered successfully!")
        username = input("Enter your username to login: ")
        password = getpass.getpass("Enter your password: ")
        if login_system.login(username, password):
            print("Login successful!")
            logged_in = True
        else:
            print("Invalid username or password!")
            return
        while True:
            print("1. Check password strength")
            print("2. Reset password")
            print("3. Logout")
            choice = input("Enter your choice: ")

            if choice == "1":
                password = getpass.getpass("Enter a password to check its strength: ")
                strength = login_system.check_password_strength(password)
                print(f"Password strength: {strength}")
            elif choice == "2":
                new_password = get_strong_password()
                login_system.reset_password(username, new_password)
            elif choice == "3":
                logged_in = False
                print("Logged out successfully!")
                return
            else:
                print("Invalid choice! Please try again.")

if __name__ == "__main__":
    main()
