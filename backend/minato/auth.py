from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from eth_account import Account
import pyotp
from authy.api import AuthyApiClient

from models import User  # Assuming you have a User model defined in a separate file

auth_blueprint = Blueprint('auth', __name__)
authy_api = AuthyApiClient('<your_authy_api_key>')

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

@auth_blueprint.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username_or_email = data.get('username_or_email')
    password = data.get('password')

    if not username_or_email or not password:
        return jsonify({'error': 'Missing required fields.'}), 400

    # Check if the user exists by username or email
    user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid username, email, or password.'}), 401

    # Check if 2FA is enabled for the user
    if user.two_factor_auth_enabled:
        return jsonify({'status': '2fa_required', 'user_id': user.id})

    # Create an access token for the user
    access_token = create_access_token(identity=user.id)
    return jsonify({'access_token': access_token}), 200

@auth_blueprint.route('/verify_2fa', methods=['POST'])
def verify_2fa():
    data = request.get_json()
    user_id = data.get('user_id')
    token = data.get('token')

    if not user_id or not token:
        return jsonify({'error': 'Missing required fields.'}), 400

    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'Invalid user ID.'}), 404

    verification = authy_api.tokens.verify(user.authy_id, token)
    
    if verification.ok():
        # Create an access token for the user
        access_token = create_access_token(identity=user.id)
        return jsonify({'access_token': access_token}), 200
    else:
        return jsonify({'error': 'Invalid 2FA token.'}), 401
    
@auth_blueprint.route('/enable_2fa', methods=['POST'])
@jwt_required()
def enable_2fa():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'Invalid user ID.'}), 404

    if user.two_factor_auth_enabled:
        return jsonify({'error': '2FA is already enabled for this user.'}), 400

    phone_number = request.form.get('phone_number')
    country_code = request.form.get('country_code')

    if not phone_number or not country_code:
        return jsonify({'error': 'Missing required fields.'}), 400

    authy_user = authy_api.users.create(user.email, phone_number, country_code)

    if authy_user.ok():
        user.two_factor_auth_enabled = True
        user.authy_id = authy_user.id
        db.session.commit()

        return jsonify({'message': '2FA enabled successfully.'}), 200
    else:
        return jsonify({'error': 'Failed to enable 2FA.'}), 400

@auth_blueprint.route('/disable_2fa', methods=['POST'])
@jwt_required()
def disable_2fa():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'Invalid user ID.'}), 404

    if not user.two_factor_auth_enabled:
        return jsonify({'error': '2FA is not enabled for this user.'}), 400

    user.two_factor_auth_enabled = False
    user.authy_id = None
    db.session.commit()

    return jsonify({'message': '2FA disabled successfully.'}), 200


@auth_blueprint.route('/login_crypto_wallet', methods=['POST'])
def login_crypto_wallet():
    data = request.get_json()
    public_address = data.get('public_address')
    signed_message = data.get('signed_message')

    if not public_address or not signed_message:
        return jsonify({'error': 'Missing required fields.'}), 400

    # Check if the user exists
    user = User.query.filter_by(public_address=public_address).first()
    if not user:
        return jsonify({'error': 'Invalid public address.'}), 401

    # Verify the signed message
    message = f"Please sign this message to log in: {user.username}"
    try:
        signer = Account.recover_message(text=message, signature=signed_message)
    except:
        return jsonify({'error': 'Invalid signature.'}), 401

    if signer.lower() != public_address.lower():
        return jsonify({'error': 'Invalid signature.'}), 401

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
    client_id='<path-to-client-id>',
    client_secret='<path-to-secret>',
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

