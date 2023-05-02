from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth

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

@auth_blueprint.route('/google/callback')
def google_callback():
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()

    # Check if the user exists
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid username or password.'}), 401

    # Create an access token for the user
    access_token = create_access_token(identity=user.id)

    return jsonify({'access_token': access_token})

@auth_blueprint.route('/google/login')
def google_login():
    redirect_uri = url_for('auth.google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

# Initialize the OAuth object
oauth = OAuth()

# Set up the Google OAuth client
google = oauth.register(
    name='google',
    client_id='263177419436-9b1tegoqb1r8ijnmi24aakl31aorpagv.apps.googleusercontent.com',
    client_secret='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',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
)

# Add the Google OAuth client to your Flask app
oauth.init_app(app)

