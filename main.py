# from lib2to3.btm_utils import tokens

from flask import Flask, request, jsonify, make_response, g
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
user_tokens = {}
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
            user_tokens[username]=token
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



# Private route that requires authentication
# @app.before_request
# def check_authentication():
#     print('user_tokens are', user_tokens)
#     token = request.headers.get('Authorization')
#     print('the current token is ',token)
#     if token and token in user_tokens:
#         g.current_user = user_tokens[token]
#     else:
#         g.current_user = None

# # ...

# # A sample private route that requires authentication
# @app.route('/private', methods=['GET'])
# def private_route():
#     if g.current_user:
#         return jsonify({'message': 'Welcome to the private route, ' + g.current_user}), 200
#     else:
#         return jsonify({'message': 'Unauthorized'}), 401

@app.route('/private', methods=['GET'])
def private():
    print('user_tokens are', user_tokens)
    token = request.headers.get('Authorization')
    print('the current token is ',token)
    if token is None:
        return jsonify({'message': 'Authorization token is missing'}), 401

    for username, user_token in user_tokens.items():
        # print('----> the actual token is ',type(token))
        # print('<---- the user token is ',type(user_token))
        print('lets check ', token==user_token)
        if token==user_token:
            print({'message': f'Hello, {username}! This is a private route.'})
            return jsonify({'message': f'Hello, {username}! This is a private route.'}), 200
        # else:
        #     print({'message': f'Hello, {username}! This is a private route.'})

    return jsonify({'message': 'Invalid token'}), 401

#     print('The Token is \n',token)

#     # # Check the token (in a real application, you'd use a library like PyJWT)
#     # if token is None or not token == SECRET_KEY:
#     #     return jsonify({'message': 'Unauthorized'}), 401

#     # return jsonify({'message': 'Welcome to the private route!'})

@app.route('/users', methods=['GET'])
def get_users():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, username FROM users')
    users = cursor.fetchall()
    conn.close()
    # Convert the list of users to a dictionary for JSON response
    user_list = [{'id': user[0], 'username': user[1]} for user in users]
    return jsonify({'users': user_list}), 200



# ...

# Generate a unique token for password reset
def generate_reset_token():
    return secrets.token_hex(16)


# Request password reset route
@app.route('/request_password_reset', methods=['POST'])
def request_password_reset():
    data = request.get_json()
    username = data['username']

    # Check if the user exists
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()

    if user:
        # Generate a reset token
        reset_token = generate_reset_token()
        
        # Store the reset token in the dictionary
        reset_tokens[reset_token] = username
        # In a real-world scenario, you would send the reset token to the user's email
        # For simplicity, we'll just return it in the response
        return jsonify({'message': 'Password reset requested', 'reset_token': reset_token}), 200
    else:
        conn.close()
        return jsonify({'message': 'User not found'}), 404

# Set new password route
@app.route('/set_new_password', methods=['POST'])
def set_new_password():
    data = request.get_json()
    reset_token = data['reset_token']
    new_password = data['new_password']

    # Check if the reset token exists
    if reset_token in reset_tokens:
        username = reset_tokens[reset_token]

        # Generate a new password hash
        hashed_password, salt_password = hash_password(new_password)

        # Update the user's password in the database
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET password = ?, salt_password = ? WHERE username = ?', (hashed_password, salt_password, username))
        conn.commit()
        conn.close()

        # Remove the reset token from the dictionary
        reset_tokens.pop(reset_token, None)

        return jsonify({'message': 'Password reset successful'}), 200
    else:
        return jsonify({'message': 'Invalid or expired reset token'}), 400

@app.route('/delete_user/<username>', methods=['DELETE'])
def delete_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Check if the user exists
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()

    if user:
        user_id = user[0]
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        return jsonify({'message': f'User with username {username} deleted successfully'}), 200
    else:
        conn.close()
        return jsonify({'message': f'User with username {username} not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)

# ...


# # Password reset route
# @app.route('/reset-password', methods=['POST'])
# def reset_password():
#     data = request.get_json()
#     username = data['username']

#     if username not in users:
#         return jsonify({'message': 'Username does not exist'}), 400

#     # Generate a reset token and store it for the user
#     reset_token = generate_reset_token()
#     reset_tokens[username] = reset_token

#     return jsonify({'message': 'Password reset token generated', 'reset_token': reset_token}), 200

# # Function to set a new password using the reset token
# @app.route('/set-new-password', methods=['POST'])
# def set_new_password():
#     data = request.get_json()
#     username = data['username']
#     reset_token = data['reset_token']
#     new_password = data['new_password']

#     if username not in reset_tokens or reset_tokens[username] != reset_token:
#         return jsonify({'message': 'Invalid reset token'}), 401

#     # Update the user's password with the new password
#     users[username] = hash_password(new_password)

    # # Remove the reset token
    # del reset_tokens[username]

    # return jsonify({'message': 'Password reset successful'}), 200

    # ... (Existing routes)

# if __name__ == '__main__':
#     app.run(debug=True)
#     # Convert the list of users to a dictionary for JSON response
#     user_list = [{'id': user[0], 'username': user[1]} for user in users]
#     print(jsonify({'users': user_list}), 200)

