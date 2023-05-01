from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash

from models import User  # Assuming you have a User model defined in a separate file

auth_blueprint = Blueprint('auth', __name__)

@auth_blueprint.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'error': 'Missing required fields.'}), 400

    # Check if the user already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'error': 'Username already taken.'}), 400

    # Hash the password and create a new user object
    hashed_password = generate_password_hash(password, method='sha256')
    new_user = User(username=username, email=email, password=hashed_password)

    # Save the user to the database
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully.'}), 201

@auth_blueprint.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Missing required fields.'}), 400

    # Check if the user exists
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid username or password.'}), 401

    # Create an access token for the user
    access_token = create_access_token(identity=user.id)

    return jsonify({'access_token': access_token}), 200

@auth_blueprint.route('/protected')
@jwt_required()
def protected():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    return jsonify({'message': f'Hello, {user.username}! This endpoint is protected.'}), 200

