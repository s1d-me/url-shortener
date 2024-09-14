import string
import random
import hashlib
import datetime
import pyotp
import uuid
import hmac
from cryptography.fernet import Fernet
from functools import wraps
from flask import request, current_user
from app import limiter, cipher_suite

def generate_short_code(length, allow_numbers, allow_uppercase, allow_lowercase):
    characters = ''

    if allow_numbers:
        characters += string.digits

    if allow_uppercase:
        characters += string.ascii_uppercase

    if allow_lowercase:
        characters += string.ascii_lowercase

    if not characters:
        characters = string.ascii_letters + string.digits

    return ''.join(random.choice(characters) for _ in range(length))

def require_api_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return 'API token is missing', 401

        conn = get_db_connection(DATABASE)
        valid_token = conn.execute('SELECT 1 FROM api_tokens WHERE token = ?', (token,)).fetchone()
        conn.close()

        if not valid_token:
            return 'Invalid API token', 403

        return f(*args, **kwargs)
    return decorated_function

def get_rate_limit(tier):
    limits = {
        'anon': app.config['ANON_RATE_LIMIT'],
        'free': app.config['FREE_TIER_RATE_LIMIT'],
        'premium': app.config['PREMIUM_TIER_RATE_LIMIT'],
        'enterprise': app.config['ENTERPRISE_TIER_RATE_LIMIT'],
        'admin': app.config['ADMIN_TIER_RATE_LIMIT']
    }
    return limits.get(tier, app.config['ANON_RATE_LIMIT'])

def apply_rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = current_user.id if current_user.is_authenticated else None
        tier = get_user_tier(user_id) if user_id else 'anon'
        rate_limit = get_rate_limit(tier)

        print(f"Applying rate limit: {rate_limit}")
        print(f"User tier: {tier}")

        return limiter.limit(rate_limit)(f)(*args, **kwargs)
    return decorated_function
