from flask import Flask, request, jsonify, make_response
import uuid
import hashlib
from flask_jwt_extended import jwt_required

app = Flask(__name__)

# Simple in-memory database for demonstration purposes
users = {}
tokens = {}

# Secret key for generating tokens (in a real application, use a secure secret key)
SECRET_KEY = 'your_secret_key'

# Function to generate a hashed password
def hash_password(password):
    salt = uuid.uuid4().hex
    return hashlib.sha256(salt.encode() + password.encode()).hexdigest() + ':' + salt

# Function to verify a hashed password
def verify_password(hashed_password, provided_password):
    password, salt = hashed_password.split(':')
    return password == hashlib.sha256(salt.encode() + provided_password.encode()).hexdigest()

# Sign-up route
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data['username']
    password = data['password']

    if username in users:
        return jsonify({'message': 'Username already exists'}), 400

    hashed_password = hash_password(password)
    users[username] = hashed_password

    return jsonify({'message': 'User registered successfully'}), 201

# Sign-in route
@app.route('/signin', methods=['POST'])
def signin():
    data = request.get_json()
    username = data['username']
    password = data['password']

    if username not in users:
        return jsonify({'message': 'Username does not exist'}), 401

    if verify_password(users[username], password):
        # Generate a token (in a real application, use a library like PyJWT)
        token = hashlib.sha256(SECRET_KEY.encode() + username.encode()).hexdigest()
        tokens[username] = token
        return jsonify({'message': 'Sign-in successful', 'token': token}), 200

    return jsonify({'message': 'Invalid password'}), 401

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
    user_list = list(users.keys())  # Get a list of all usernames
    return jsonify({'users': user_list}), 200

if __name__ == '__main__':
    app.run(debug=True)
