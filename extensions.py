from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO # <-- ADD THIS IMPORT

# Create database instance
db = SQLAlchemy()

# Create login manager instance
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Create bcrypt instance for password hashing
bcrypt = Bcrypt()

# Create SocketIO instance
socketio = SocketIO() # <-- ADD THIS LINE