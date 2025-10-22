import os
from dotenv import load_dotenv

# Load environment variables from a .env file at the project root
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class Config:
    """
    Configuration class for the Flask application.
    Loads settings from environment variables for security and flexibility.
    """
    
    # --- Critical Security Configurations ---

    # Secret Key for session management, CSRF protection, etc.
    # This is loaded from the .env file and is essential for security.
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess-this'

    # Fernet key for the server-side encryption demonstration.
    # This MUST be set in your .env file.
    FERNET_KEY = os.environ.get('FERNET_KEY')
    if not FERNET_KEY:
        raise ValueError("No FERNET_KEY set. Please generate one and add it to your .env file.")

    # --- Database Configurations ---
    
    # Database URI for SQLAlchemy.
    # Defaults to a local SQLite database if DATABASE_URL is not set.
    # For production, set DATABASE_URL to your PostgreSQL connection string.
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'securechat.db')

    # Disable SQLAlchemy's event system to save resources, as it's not needed for our use case.
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- Cybersecurity Feature Configurations ---

    # A set of keywords that will trigger a security alert in the chat.
    CYBERCRIME_KEYWORDS = {
        "hack", "malware", "phish", "phishing", "exploit", "keylogger",
        "botnet", "trojan", "virus", "ransomware", "spyware", "ddos",
        "dark web", "carding", "social security", "password"
    }