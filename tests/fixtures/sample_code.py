"""Test fixtures for agent testing."""

VULNERABLE_CODE_SQL_INJECTION = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id={user_id}"
    return db.execute(query)
'''

VULNERABLE_CODE_XSS = '''
def display_user_profile(username):
    return f"<h1>Welcome {username}!</h1>"
'''

VULNERABLE_CODE_COMMAND_INJECTION = '''
import os

def backup_file(filename):
    os.system(f"tar -czf backup.tar.gz {filename}")
'''

VULNERABLE_CODE_WEAK_CRYPTO = '''
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
'''

VULNERABLE_CODE_EVAL = '''
def execute_user_code(code):
    return eval(code)
'''

SAFE_CODE = '''
def get_user_safe(user_id):
    cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
    return cursor.fetchone()
'''
