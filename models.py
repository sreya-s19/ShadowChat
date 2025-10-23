import datetime
from cryptography.fernet import Fernet
from flask import current_app
from flask_login import UserMixin
from extensions import db, bcrypt, login_manager

@login_manager.user_loader
def load_user(user_id):
    """Flask-Login hook to load a user from the database."""
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    """User model for storing user accounts."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    
    # Relationships
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    messages_received = db.relationship('Message', foreign_keys='Message.recipient_id', backref='recipient', lazy=True)

    def set_password(self, password):
        """Hashes the password and stores it."""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return bcrypt.check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Message(db.Model):
    """Message model for storing conversations."""
    __tablename__ = 'messages'

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    body = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.datetime.utcnow)
    is_encrypted = db.Column(db.Boolean, default=False, nullable=False)

    def encrypt_body(self, plaintext_body):
        """Encrypts the message body using the app's Fernet key."""
        fernet = Fernet(current_app.config['FERNET_KEY'].encode())
        self.body = fernet.encrypt(plaintext_body.encode()).decode()
        self.is_encrypted = True

    def decrypt_body(self):
        """Decrypts the message body if it is encrypted."""
        if self.is_encrypted:
            try:
                fernet = Fernet(current_app.config['FERNET_KEY'].encode())
                return fernet.decrypt(self.body.encode()).decode()
            except Exception:
                return "[Decryption Error: Unable to read message]"
        return self.body

    def __repr__(self):
        return f'<Message from {self.sender_id} to {self.recipient_id}>'