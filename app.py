import hashlib
import sqlite3

password = "admin123"
hashed = hashlib.md5(password.encode()).hexdigest()

def login(user_input):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + user_input + "'")
    return cursor.fetchall()

def store_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()

def read_file(filename):
    f = open(filename, "r")
    data = f.read()
    return data
