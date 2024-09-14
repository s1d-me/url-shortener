from flask import Flask
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for session management

# Load configuration from a config file
app.config.from_pyfile('../config.py')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Encryption key for API tokens
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

# Initialize Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

from app import routes, models
