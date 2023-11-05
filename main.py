# from lib2to3.btm_utils import tokens

from flask import Flask, request, jsonify, make_response
import uuid
import sqlite3
import secrets
import hashlib
import secrets
from werkzeug.datastructures import auth

app = Flask(__name__)
# Initialize the SQLite database
conn = sqlite3.connect('users.db')
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        salt_password TEXT NOT NULL
    )
''')
conn.commit()
conn.close()

# Secret key for password hashing and token generation
SECRET_KEY = secrets.token_hex(16)

def generate_reset_token():
    return secrets.token_urlsafe(32)

# Simple dictionary to store reset tokens
reset_tokens = {}

# Function to generate a hashed password
def hash_password(password):
    salt = secrets.token_hex(16)
    salted_password = password + salt
    hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
    return hashed_password, salt
# Function to verify a hashed password
def verify_password(hashed_password, provided_password):
    password, salt = hashed_password.split(':')
    return password == hashlib.sha256(salt.encode() + provided_password.encode()).hexdigest()

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data['username']
    password = data['password']
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    existing_user = cursor.fetchone()

    if existing_user:
        conn.close()
        return jsonify({'message': 'Username already exists'}), 400

    hashed_password, salt = hash_password(password)

    cursor.execute('INSERT INTO users (username, password, salt_password) VALUES (?, ?, ?)', (username, hashed_password, salt))
    conn.commit()
    conn.close()

    return jsonify({'message': 'User registered successfully'}), 201

# Sign-in route
@app.route('/signin', methods=['POST'])
def signin():
    data = request.get_json()
    username = data['username']
    password = data['password']

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        print(user)
        hashed_password = user[2]
        salted_password = password + user[3]
        if hashlib.sha256(salted_password.encode()).hexdigest() == hashed_password:
            # Generate a JSON Web Token (JWT) for authentication
            token = secrets.token_hex(16)
            return jsonify({'message': 'Sign in successful', 'token': token}), 200

    return jsonify({'message': 'Invalid username or password'}), 401

# Route to delete a table in the database
@app.route('/delete_table/<table_name>', methods=['DELETE'])
def delete_table(table_name):
    conn = sqlite3.connect('your_database.db')
    cursor = conn.cursor()

    try:
        # Use the provided table name to construct the SQL command to delete the table
        cursor.execute(f'DROP TABLE IF EXISTS {table_name}')
        conn.commit()
        conn.close()

        return jsonify({'message': f'Table {table_name} deleted successfully'}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)

# Private route that requires authentication
@app.route('/private', methods=['GET'])
def private():
    token = request.headers.get('Authorization')

    if token is None:
        return jsonify({'message': 'Authorization token is missing'}), 401

    for username, user_token in tokens.items():
        if token == user_token:
            return jsonify({'message': f'Hello, {username}! This is a private route.'}), 200

    return jsonify({'message': 'Invalid token'}), 401

@app.route('/users', methods=['GET'])
def get_users():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, username FROM users')
    users = cursor.fetchall()
    conn.close()

    # Password reset route
    @app.route('/reset-password', methods=['POST'])
    def reset_password():
        data = request.get_json()
        username = data['username']

        if username not in users:
            return jsonify({'message': 'Username does not exist'}), 400

        # Generate a reset token and store it for the user
        reset_token = generate_reset_token()
        reset_tokens[username] = reset_token

        return jsonify({'message': 'Password reset token generated', 'reset_token': reset_token}), 200

    # Function to set a new password using the reset token
    @app.route('/set-new-password', methods=['POST'])
    def set_new_password():
        data = request.get_json()
        username = data['username']
        reset_token = data['reset_token']
        new_password = data['new_password']

        if username not in reset_tokens or reset_tokens[username] != reset_token:
            return jsonify({'message': 'Invalid reset token'}), 401

        # Update the user's password with the new password
        users[username] = hash_password(new_password)

        # Remove the reset token
        del reset_tokens[username]

        return jsonify({'message': 'Password reset successful'}), 200

    # ... (Existing routes)

    if __name__ == '__main__':
        app.run(debug=True)
    # Convert the list of users to a dictionary for JSON response
    user_list = [{'id': user[0], 'username': user[1]} for user in users]

    return jsonify({'users': user_list}), 200

