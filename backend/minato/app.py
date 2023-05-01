from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_restful import Api, Resource
from flask_socketio import SocketIO

from user import db
from auth import auth_blueprint

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db.init_app(app)
with app.app_context():
    db.create_all()
app.register_blueprint(auth_blueprint, url_prefix='/auth')
jwt = JWTManager(app)
api = Api(app)
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app)

@app.route('/')
def index():
    return jsonify({'message': 'Welcome to the Flask API!'})

if __name__ == '__main__':
    CORS(app)
    socketio.run(app, debug=True)

    print("Index function was called")

    
