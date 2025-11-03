"""
User database management utilities.
Handles loading and saving user data from JSON file.
"""

import json


def load_users():
    """
    Load users from JSON file.
    
    Returns:
        dict - Dictionary of users, or empty dict if file not found
    """
    try:
        with open('users.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_users(users_db):
    """
    Save users to JSON file.
    
    Args:
        users_db: dict - Dictionary of users to save
    """
    with open('users.json', 'w') as f:
        json.dump(users_db, f)