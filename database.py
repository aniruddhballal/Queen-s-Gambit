import json
import os
from config import Config

class UserDatabase:
    def __init__(self, db_file=Config.USERS_DB_FILE):
        self.db_file = db_file
        self.users = self._load_users()
    
    def _load_users(self):
        try:
            with open(self.db_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def save_users(self):
        with open(self.db_file, 'w') as f:
            json.dump(self.users, f)
    
    def user_exists(self, username):
        return username in self.users
    
    def add_user(self, username, password, email):
        self.users[username] = {
            'password': password,
            'email': email
        }
        self.save_users()
    
    def get_user(self, username):
        return self.users.get(username)
    
    def delete_user(self, username):
        if username in self.users:
            del self.users[username]
            self.save_users()
            return True
        return False
    
    def verify_credentials(self, username, password):
        user = self.get_user(username)
        return user and user['password'] == password
    
    def get_all_users(self):
        return self.users