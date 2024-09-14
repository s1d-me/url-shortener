import sqlite3
import string
import random
import hashlib
import datetime
import pyotp
import uuid
import hmac
from flask_login import UserMixin
from cryptography.fernet import Fernet
from functools import wraps

DATABASE = 'url_shortener.db'
BLOCKED_DOMAINS_DB = 'blocked_domains.db'

class User(UserMixin):
    def __init__(self, id, username, password, email, tier, two_factor_secret, salt):
        self.id = id
        self.username = username
        self.password = password
        self.email = email
        self.tier = tier
        self.two_factor_secret = two_factor_secret
        self.salt = salt

    def get_token_count(self):
        conn = get_db_connection(DATABASE)
        count = conn.execute('SELECT COUNT(*) FROM api_tokens WHERE user_id = ?', (self.id,)).fetchone()[0]
        conn.close()
        return count

def get_db_connection(db_name):
    conn = sqlite3.connect(db_name)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        conn = get_db_connection(DATABASE)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                tier TEXT DEFAULT 'free',
                two_factor_secret TEXT,
                api_token TEXT,
                salt TEXT,
                recovery_codes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS url_mapping (
                short_code TEXT PRIMARY KEY,
                original_url TEXT,
                ip_address TEXT,
                click_count INTEGER DEFAULT 0,
                api_token TEXT,
                expiry_time TIMESTAMP,
                password TEXT,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS api_tokens (
                token TEXT PRIMARY KEY,
                link_count INTEGER DEFAULT 0,
                click_count INTEGER DEFAULT 0,
                user_id INTEGER,
                username TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')

        conn.commit()
        conn.close()

        conn = get_db_connection(BLOCKED_DOMAINS_DB)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS blocked_domains (
                domain TEXT PRIMARY KEY
            )
        ''')

        conn.commit()
        conn.close()

        # Create root user
        conn = get_db_connection(DATABASE)
        root_user = conn.execute('SELECT * FROM users WHERE username = ?', ('root',)).fetchone()
        if not root_user:
            salt = os.urandom(16).hex()
            root_password_hash = hashlib.sha256((salt + 'root_password').encode()).hexdigest()

            conn.execute('INSERT INTO users (username, password, email, tier, salt) VALUES (?, ?, ?, ?, ?)',
                        ('root', root_password_hash, 'root@s1d.me', 'admin', salt))
            conn.commit()
        conn.close()

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def is_blocked_domain(url):
    conn = get_db_connection(BLOCKED_DOMAINS_DB)
    domain = urlparse(url).netloc

    blocked = conn.execute('SELECT 1 FROM blocked_domains WHERE ? LIKE (domain || \'.%\') OR domain = ?', (domain, domain)).fetchone()
    conn.close()
    return blocked is not None

def get_user_tier(user_id):
    conn = get_db_connection(DATABASE)
    user = conn.execute('SELECT tier FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return user['tier'] if user else None

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
