from flask import Flask, request, redirect, url_for, render_template, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import string
import random
import os
from functools import wraps
from urllib.parse import urlparse
import hashlib
import datetime
import pyotp
import uuid
import hmac
from cryptography.fernet import Fernet
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for session management

# Load configuration from a config file
app.config.from_pyfile('config.py')

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

class User(UserMixin):
    def __init__(self, id, username, password, email, tier, two_factor_secret, salt):
        self.id = id
        self.username = username
        self.password = password
        self.email = email
        self.tier = tier
        self.two_factor_secret = two_factor_secret
        self.salt = salt

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    if user:
        return User(user['id'], user['username'], user['password'], user['email'], user['tier'], user['two_factor_secret'], user['salt'])
    return None

def get_db_connection():
    conn = psycopg2.connect(
        dbname=app.config['DB_NAME'],
        user=app.config['DB_USER'],
        password=app.config['DB_PASSWORD'],
        host=app.config['DB_HOST'],
        port=app.config['DB_PORT']
    )
    return conn

def init_db():
    with app.app_context():
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                tier TEXT DEFAULT 'free',
                two_factor_secret TEXT,
                api_token TEXT,
                salt TEXT,
                recovery_codes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
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

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_tokens (
                token TEXT PRIMARY KEY,
                link_count INTEGER DEFAULT 0,
                click_count INTEGER DEFAULT 0,
                user_id INTEGER,
                username TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_domains (
                domain TEXT PRIMARY KEY
            )
        ''')

        conn.commit()
        cursor.close()
        conn.close()

        # Create root user
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s', ('root',))
        root_user = cursor.fetchone()
        if not root_user:
            salt = os.urandom(16).hex()
            root_password_hash = hashlib.sha256((salt + 'root_password').encode()).hexdigest()

            cursor.execute('INSERT INTO users (username, password, email, tier, salt) VALUES (%s, %s, %s, %s, %s)',
                          ('root', root_password_hash, 'root@s1d.me', 'admin', salt))
            conn.commit()
        cursor.close()
        conn.close()

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def is_blocked_domain(url):
    conn = get_db_connection()
    cursor = conn.cursor()
    domain = urlparse(url).netloc

    cursor.execute('SELECT 1 FROM blocked_domains WHERE %s LIKE (domain || \'.%\') OR domain = %s', (domain, domain))
    blocked = cursor.fetchone()
    cursor.close()
    conn.close()
    return blocked is not None

def get_user_tier(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT tier FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    cursor.close()
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

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM api_tokens WHERE token = %s', (token,))
        valid_token = cursor.fetchone()
        cursor.close()
        conn.close()

        if not valid_token:
            return 'Invalid API token', 403

        return f(*args, **kwargs)
    return decorated_function

def get_rate_limit(tier):
    limits = {
        'free': app.config['FREE_TIER_RATE_LIMIT'],
        'premium': app.config['PREMIUM_TIER_RATE_LIMIT'],
        'enterprise': app.config['ENTERPRISE_TIER_RATE_LIMIT'],
        'admin': app.config['ADMIN_TIER_RATE_LIMIT']
    }
    return limits.get(tier, app.config['DEFAULT_RATE_LIMIT'])

def apply_rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = current_user.id if current_user.is_authenticated else None
        tier = get_user_tier(user_id) if user_id else 'free'
        rate_limit = get_rate_limit(tier)

        print(f"Applying rate limit: {rate_limit}")
        print(f"User tier: {tier}")

        return limiter.limit(rate_limit)(f)(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/gen')
def index():
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT * FROM url_mapping')
    urls = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('gen.html', urls=urls)

@app.route('/api')
def api():
    return render_template('api.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        if not username or not password or not email:
            return 'All fields are required', 400

        salt = os.urandom(16).hex()
        password_hash = hashlib.sha256((salt + password).encode()).hexdigest()

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password, email, salt) VALUES (%s, %s, %s, %s)',
                           (username, password_hash, email, salt))
            conn.commit()
        except psycopg2.IntegrityError:
            return 'Username or email already exists', 400
        finally:
            cursor.close()
            conn.close()

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and hmac.compare_digest(user['password'], hashlib.sha256((user['salt'] + password).encode()).hexdigest()):
            user_obj = User(user['id'], user['username'], user['password'], user['email'], user['tier'], user['two_factor_secret'], user['salt'])
            login_user(user_obj)

            if user['two_factor_secret']:
                return redirect(url_for('verify_2fa'))

            if current_user.tier == 'admin':
                return redirect(url_for('admin_dashboard'))

            return redirect(url_for('dashboard'))

        return 'Invalid username or password', 401

    return render_template('login.html')

@app.route('/verify_2fa', methods=['GET', 'POST'])
@login_required
def verify_2fa():
    if request.method == 'POST':
        code = request.form['code']
        totp = pyotp.TOTP(current_user.two_factor_secret)

        if totp.verify(code):
            return redirect(url_for('dashboard'))
        else:
            return 'Invalid code', 400

    return render_template('verify_2fa.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = current_user.id
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT * FROM url_mapping WHERE user_id = %s', (user_id,))
    urls = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('dashboard.html', urls=urls)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/shorten', methods=['POST'])
@apply_rate_limit
def shorten():
    return shorten_internal()

def shorten_internal():
    user_id = current_user.id if current_user.is_authenticated else None

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    original_url = request.form['url']
    custom_code = request.form.get('custom_code')
    password = request.form.get('password')
    expiry_time = request.form.get('expiry_time')

    if 'Authorization' in request.headers:
        return 'This route is not intended for API use', 403

    length = int(request.form['length'])
    allow_numbers = 'allow_numbers' in request.form
    allow_uppercase = 'allow_uppercase' in request.form
    allow_lowercase = 'allow_lowercase' in request.form

    if not is_valid_url(original_url):
        return 'Invalid URL', 400

    if is_blocked_domain(original_url):
        return 'Blocked domain', 400

    ip_address = request.remote_addr

    characters = ''
    if allow_numbers:
        characters += string.digits
    if allow_uppercase:
        characters += string.ascii_uppercase
    if allow_lowercase:
        characters += string.ascii_lowercase

    if not characters:
        characters = string.ascii_letters + string.digits

    if not expiry_time:
        expiry_time = None

    total_combinations = len(characters) ** length

    cursor.execute('SELECT COUNT(*) FROM url_mapping')
    existing_codes_count = cursor.fetchone()[0]

    if existing_codes_count >= total_combinations:
        options_message = f"Length: {length}, Allow Numbers: {allow_numbers}, Allow Uppercase: {allow_uppercase}, Allow Lowercase: {allow_lowercase}"
        return f'No other possible combination of {length} characters with the selected options is available. Selected options: {options_message}', 400

    if custom_code:
        short_code = custom_code
        cursor.execute('SELECT 1 FROM url_mapping WHERE short_code = %s', (short_code,))
        if cursor.fetchone() is not None:
            return 'Custom code already exists. Please choose another one.', 400
    else:
        short_code = generate_short_code(length, allow_numbers, allow_uppercase, allow_lowercase)
        while cursor.execute('SELECT 1 FROM url_mapping WHERE short_code = %s', (short_code,)).fetchone() is not None:
            short_code = generate_short_code(length, allow_numbers, allow_uppercase, allow_lowercase)

    if password:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
    else:
        password_hash = None

    cursor.execute('INSERT INTO url_mapping (short_code, original_url, ip_address, expiry_time, password, user_id) VALUES (%s, %s, %s, %s, %s, %s)',
                   (short_code, original_url, ip_address, expiry_time, password_hash, user_id))
    conn.commit()
    cursor.close()
    conn.close()

    if user_id is not None:
        return redirect(url_for('dashboard'))

    if user_id is None:
        return f"The Short Code is \n https://s1d.me/{short_code}"

@app.route('/<code>')
def redirect_to_url(code):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT original_url, click_count, expiry_time, password FROM url_mapping WHERE short_code = %s', (code,))
    url = cursor.fetchone()

    if url:
        if url['expiry_time'] and datetime.datetime.now() > datetime.datetime.strptime(url['expiry_time'], '%Y-%m-%d %H:%M:%S'):
            cursor.execute('DELETE FROM url_mapping WHERE short_code = %s', (code,))
            cursor.execute('UPDATE api_tokens SET link_count = link_count - 1 WHERE token = (SELECT api_token FROM url_mapping WHERE short_code = %s)', (code,))
            conn.commit()
            cursor.close()
            conn.close()
            return 'URL has expired', 404

        if url['password']:
            cursor.close()
            conn.close()
            return render_template('password.html', code=code)

        cursor.execute('UPDATE url_mapping SET click_count = click_count + 1 WHERE short_code = %s', (code,))
        cursor.execute('UPDATE api_tokens SET click_count = click_count + 1 WHERE token = (SELECT api_token FROM url_mapping WHERE short_code = %s)', (code,))
        conn.commit()
        cursor.close()
        conn.close()
        return redirect(url['original_url'])

    else:
        cursor.close()
        conn.close()
        return 'URL not found', 404

@app.route('/check_password', methods=['POST'])
def check_password():
    code = request.form['code']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT original_url, password FROM url_mapping WHERE short_code = %s', (code,))
    url = cursor.fetchone()

    if url and url['password'] == hashlib.sha256(password.encode()).hexdigest():
        cursor.execute('UPDATE url_mapping SET click_count = click_count + 1 WHERE short_code = %s', (code,))
        cursor.execute('UPDATE api_tokens SET click_count = click_count + 1 WHERE token = (SELECT api_token FROM url_mapping WHERE short_code = %s)', (code,))
        conn.commit()
        cursor.close()
        conn.close()
        return redirect(url['original_url'])

    cursor.close()
    conn.close()
    return 'Incorrect password', 403

@app.route('/api/shorten', methods=['POST'])
@require_api_token
@apply_rate_limit
def api_shorten():
    return api_shorten_internal()

def api_shorten_internal():
    data = request.json
    original_url = data.get('url')
    length = int(data.get('length', 6))
    allow_numbers = data.get('allow_numbers', True)
    allow_uppercase = data.get('allow_uppercase', True)
    allow_lowercase = data.get('allow_lowercase', True)
    expiry_time = data.get('expiry_time')

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    ip_address = request.remote_addr
    token = request.headers.get('Authorization')

    cursor.execute('SELECT user_id FROM api_tokens WHERE token = %s', (token,))
    user_id_row = cursor.fetchone()
    if user_id_row is None:
        cursor.close()
        conn.close()
        return 'Invalid API token', 403

    user_id = user_id_row['user_id']

    if not is_valid_url(original_url):
        cursor.close()
        conn.close()
        return 'Invalid URL', 400

    if is_blocked_domain(original_url):
        cursor.close()
        conn.close()
        return 'Blocked domain', 400

    characters = ''
    if allow_numbers:
        characters += string.digits
    if allow_uppercase:
        characters += string.ascii_uppercase
    if allow_lowercase:
        characters += string.ascii_lowercase

    if not characters:
        characters = string.ascii_letters + string.digits

    total_combinations = len(characters) ** length

    cursor.execute('SELECT COUNT(*) FROM url_mapping')
    existing_codes_count = cursor.fetchone()[0]
    if existing_codes_count >= total_combinations:
        options_message = f"Length: {length}, Allow Numbers: {allow_numbers}, Allow Uppercase: {allow_uppercase}, Allow Lowercase: {allow_lowercase}"
        cursor.close()
        conn.close()
        return f'No other possible combination of {length} characters with the selected options is available. Selected options: {options_message}', 400

    short_code = generate_short_code(length, allow_numbers, allow_uppercase, allow_lowercase)
    while cursor.execute('SELECT 1 FROM url_mapping WHERE short_code = %s', (short_code,)).fetchone() is not None:
        short_code = generate_short_code(length, allow_numbers, allow_uppercase, allow_lowercase)

    cursor.execute('INSERT INTO url_mapping (short_code, original_url, ip_address, api_token, expiry_time, user_id) VALUES (%s, %s, %s, %s, %s, %s)',
                   (short_code, original_url, ip_address, token, expiry_time, user_id))
    cursor.execute('UPDATE api_tokens SET link_count = link_count + 1 WHERE token = %s', (token,))
    conn.commit()
    cursor.close()
    conn.close()

    return {'short_code': short_code}, 201

@app.route('/api/analytics', methods=['GET'])
@require_api_token
def api_analytics():
    token = request.headers.get('Authorization')
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    cursor.execute('SELECT link_count, click_count FROM api_tokens WHERE token = %s', (token,))
    api_data = cursor.fetchone()
    cursor.execute('SELECT short_code, original_url, click_count, expiry_time FROM url_mapping WHERE api_token = %s', (token,))
    links = cursor.fetchall()

    analytics = {
        'link_count': api_data['link_count'],
        'click_count': api_data['click_count'],
        'links': [{'short_code': link['short_code'], 'original_url': link['original_url'], 'click_count': link['click_count'], 'expiry_time': link['expiry_time']} for link in links]
    }

    cursor.close()
    conn.close()
    return jsonify(analytics)

@app.route('/reset_api_token', methods=['POST'])
@login_required
def reset_api_token():
    user_id = current_user.id
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    # Retrieve the current token and its counts
    cursor.execute('SELECT token, link_count, click_count FROM api_tokens WHERE user_id = %s', (user_id,))
    existing_token = cursor.fetchone()

    if existing_token:
        # Generate a new token
        new_token = uuid.uuid4().hex

        # Update the token but keep the counts
        cursor.execute('UPDATE api_tokens SET token = %s WHERE user_id = %s', (new_token, user_id))
        cursor.execute('UPDATE users SET api_token = %s WHERE id = %s', (new_token, user_id))
    else:
        # If no token exists, create a new one
        new_token = uuid.uuid4().hex
        cursor.execute('INSERT INTO api_tokens (token, user_id, username) VALUES (%s, %s, %s)', (new_token, user_id, current_user.username))
        cursor.execute('UPDATE users SET api_token = %s WHERE id = %s', (new_token, user_id))

    conn.commit()
    cursor.close()
    conn.close()

    return {'token': new_token}, 201

@app.route('/api_tokens')
@login_required
def api_tokens():
    user_id = current_user.id
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT * FROM api_tokens WHERE user_id = %s', (user_id,))
    tokens = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('api_tokens.html', tokens=tokens)

@app.route('/link_analytics/<short_code>')
@login_required
def link_analytics(short_code):
    user_id = current_user.id
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT * FROM url_mapping WHERE short_code = %s AND user_id = %s', (short_code, user_id))
    link = cursor.fetchone()
    cursor.close()
    conn.close()

    if not link:
        return 'Link not found', 404

    return render_template('link_analytics.html', link=link)

@app.route('/enable_2fa', methods=['GET', 'POST'])
@login_required
def enable_2fa():
    if request.method == 'POST':
        secret = request.form['secret']
        code = request.form['code']

        totp = pyotp.TOTP(secret)
        if not totp.verify(code):
            return 'Invalid code', 400

        user_id = current_user.id
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET two_factor_secret = %s WHERE id = %s', (secret, user_id))
        conn.commit()
        cursor.close()
        conn.close()

        return redirect(url_for('dashboard'))

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=current_user.username, issuer_name='URL Shortener')

    # Generate recovery codes
    recovery_codes = [uuid.uuid4().hex[:8] for _ in range(5)]
    encrypted_codes = [cipher_suite.encrypt(code.encode()).decode() for code in recovery_codes]

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET recovery_codes = %s WHERE id = %s', (','.join(encrypted_codes), current_user.id))
    conn.commit()
    cursor.close()
    conn.close()

    return render_template('enable_2fa.html', secret=secret, provisioning_uri=provisioning_uri, recovery_codes=recovery_codes)

@app.route('/admin/assign_tier', methods=['GET', 'POST'])
@login_required
def assign_tier():
    if current_user.tier != 'admin':
        return 'Access denied', 403

    if request.method == 'POST':
        user_id = request.form['user_id']
        tier = request.form['tier']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET tier = %s WHERE id = %s', (tier, user_id))
        conn.commit()
        cursor.close()
        conn.close()

        return redirect(url_for('admin_dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT id, username, tier FROM users')
    users = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('assign_tier.html', users=users)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.tier != 'admin':
        return 'Access denied', 403

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT * FROM url_mapping')
    urls = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('admin_dashboard.html', urls=urls)

@app.route('/admin/link_analytics/<short_code>')
@login_required
def admin_link_analytics(short_code):
    if current_user.tier != 'admin':
        return 'Access denied', 403

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT * FROM url_mapping WHERE short_code = %s', (short_code,))
    link = cursor.fetchone()
    cursor.close()
    conn.close()

    if not link:
        return 'Link not found', 404

    return render_template('link_analytics.html', link=link)

@app.route('/<code>/+', methods=['GET', 'POST'])
def report_malicious_link(code):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT original_url FROM url_mapping WHERE short_code = %s', (code,))
    url = cursor.fetchone()
    cursor.close()
    conn.close()

    if not url:
        return 'URL not found', 404

    if request.method == 'POST':
        reason = request.form['reason']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO reported_links (short_code, reason) VALUES (%s, %s)', (code, reason))
        conn.commit()
        cursor.close()
        conn.close()
        return 'Link reported successfully', 200

    return render_template('report_link.html', code=code, original_url=url['original_url'])

@app.route('/manage_links', methods=['GET', 'POST'])
@login_required
def manage_links():
    user_id = current_user.id
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    if request.method == 'POST':
        action = request.form['action']
        short_code = request.form['short_code']

        if action == 'delete':
            cursor.execute('DELETE FROM url_mapping WHERE short_code = %s AND user_id = %s', (short_code, user_id))
        elif action == 'modify':
            original_url = request.form['url']
            expiry_time = request.form.get('expiry_time')
            password = request.form.get('password')

            if password:
                password_hash = hashlib.sha256(password.encode()).hexdigest()
            else:
                password_hash = None

            cursor.execute('UPDATE url_mapping SET original_url = %s, expiry_time = %s, password = %s WHERE short_code = %s AND user_id = %s',
                           (original_url, expiry_time, password_hash, short_code, user_id))

        conn.commit()

    cursor.execute('SELECT * FROM url_mapping WHERE user_id = %s', (user_id,))
    urls = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('manage_links.html', urls=urls)

@app.route('/admin/manage_links', methods=['GET', 'POST'])
@login_required
def admin_manage_links():
    if current_user.tier != 'admin':
        return 'Access denied', 403

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    if request.method == 'POST':
        action = request.form['action']
        short_code = request.form['short_code']

        if action == 'delete':
            cursor.execute('DELETE FROM url_mapping WHERE short_code = %s', (short_code,))
        elif action == 'modify':
            original_url = request.form['url']
            expiry_time = request.form.get('expiry_time')
            password = request.form.get('password')

            if password:
                password_hash = hashlib.sha256(password.encode()).hexdigest()
            else:
                password_hash = None

            cursor.execute('UPDATE url_mapping SET original_url = %s, expiry_time = %s, password = %s WHERE short_code = %s',
                           (original_url, expiry_time, password_hash, short_code))

        conn.commit()

    cursor.execute('SELECT * FROM url_mapping')
    urls = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('admin_manage_links.html', urls=urls)

@app.route('/recovery_codes', methods=['GET', 'POST'])
@login_required
def recovery_codes():
    user_id = current_user.id
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    if request.method == 'POST':
        codes = request.form['codes'].split(',')
        encrypted_codes = [cipher_suite.encrypt(code.encode()).decode() for code in codes]
        cursor.execute('UPDATE users SET recovery_codes = %s WHERE id = %s', (','.join(encrypted_codes), user_id))
        conn.commit()
        cursor.close()
        conn.close()
        return 'Recovery codes saved successfully', 200

    cursor.execute('SELECT recovery_codes FROM users WHERE id = %s', (user_id,))
    recovery_codes = cursor.fetchone()
    cursor.close()
    conn.close()

    if recovery_codes and recovery_codes['recovery_codes']:
        decrypted_codes = [cipher_suite.decrypt(code.encode()).decode() for code in recovery_codes['recovery_codes'].split(',')]
        return render_template('recovery_codes.html', codes=decrypted_codes)

    return render_template('recovery_codes.html')

@app.route('/use_recovery_code', methods=['POST'])
def use_recovery_code():
    code = request.form['code']
    encrypted_code = cipher_suite.encrypt(code.encode()).decode()

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT * FROM users WHERE recovery_codes LIKE %s', (f'%{encrypted_code}%',))
    user = cursor.fetchone()

    if user:
        recovery_codes = user['recovery_codes'].split(',')
        recovery_codes.remove(encrypted_code)
        cursor.execute('UPDATE users SET recovery_codes = %s WHERE id = %s', (','.join(recovery_codes), user['id']))
        conn.commit()
        cursor.close()
        conn.close()

        user_obj = User(user['id'], user['username'], user['password'], user['email'], user['tier'], user['two_factor_secret'], user['salt'])
        login_user(user_obj)

        return 'Recovery code used successfully', 200

    cursor.close()
    conn.close()
    return 'Invalid recovery code', 400

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
