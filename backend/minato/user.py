from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Channel(db.model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('channels', lazy=True))

class User(db.Model):
    def __init__(self, email, password):
        self.email = email
        self.password = password

    public_address = db.Column(db.String, unique=True, nullable=True)
    two_factor_auth_enabled = db.Column(db.Boolean, default=False)
    authy_id = db.Column(db.String, nullable=True)
    channels = db.relationship('Channel', backref='owner', lazy=True)
    