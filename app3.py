from flask import Flask, request, redirect, url_for, render_template, jsonify
import string
import random
import sqlite3
import os
from functools import wraps
from urllib.parse import urlparse
import hashlib
import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

DATABASE = 'url_shortener.db'
BLOCKED_DOMAINS_DB = 'blocked_domains.db'

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

def get_db_connection(db_name):
    conn = sqlite3.connect(db_name)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        conn = get_db_connection(DATABASE)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS url_mapping (
                short_code TEXT PRIMARY KEY,
                original_url TEXT,
                ip_address TEXT,
                click_count INTEGER DEFAULT 0,
                api_token TEXT,
                expiry_time TIMESTAMP,
                password TEXT
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS api_tokens (
                token TEXT PRIMARY KEY,
                link_count INTEGER DEFAULT 0,
                click_count INTEGER DEFAULT 0
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

def generate_short_code(length, allow_numbers, allow_special, allow_uppercase, allow_lowercase):
    characters = ''

    if allow_numbers:
        characters += string.digits

    if allow_special:
        characters += string.punctuation

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

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/gen')
def index():
    conn = get_db_connection(DATABASE)
    urls = conn.execute('SELECT * FROM url_mapping').fetchall()
    conn.close()

    return render_template('gen.html', urls=urls)

@app.route('/api')
def api():
    return render_template('api.html')

@app.route('/shorten', methods=['POST'])
@limiter.limit("3 per 5 second")  # Rate limit for /shorten route
def shorten():
    original_url = request.form['url']
    custom_code = request.form.get('custom_code')
    password = request.form.get('password')
    expiry_time = request.form.get('expiry_time')

    if 'Authorization' in request.headers:
        return 'This route is not intended for API use', 403

    length = int(request.form['length'])
    allow_numbers = 'allow_numbers' in request.form
    allow_special = 'allow_special' in request.form
    allow_uppercase = 'allow_uppercase' in request.form
    allow_lowercase = 'allow_lowercase' in request.form

    if not is_valid_url(original_url):
        return 'Invalid URL', 400

    if is_blocked_domain(original_url):
        return 'Blocked domain', 400

    ip_address = request.remote_addr

    conn = get_db_connection(DATABASE)

    characters = ''
    if allow_numbers:
        characters += string.digits
    if allow_special:
        characters += string.punctuation
    if allow_uppercase:
        characters += string.ascii_uppercase
    if allow_lowercase:
        characters += string.ascii_lowercase

    if not characters:
        characters = string.ascii_letters + string.digits

    if not expiry_time:
        expiry_time = None

    total_combinations = len(characters) ** length

    existing_codes_count = conn.execute('SELECT COUNT(*) FROM url_mapping').fetchone()[0]

    if existing_codes_count >= total_combinations:
        options_message = f"Length: {length}, Allow Numbers: {allow_numbers}, Allow Special: {allow_special}, Allow Uppercase: {allow_uppercase}, Allow Lowercase: {allow_lowercase}"
        return f'No other possible combination of {length} characters with the selected options is available. Selected options: {options_message}', 400

    if custom_code:
        short_code = custom_code
        if conn.execute('SELECT 1 FROM url_mapping WHERE short_code = ?', (short_code,)).fetchone() is not None:
            return 'Custom code already exists. Please choose another one.', 400
    else:
        short_code = generate_short_code(length, allow_numbers, allow_special, allow_uppercase, allow_lowercase)
        while conn.execute('SELECT 1 FROM url_mapping WHERE short_code = ?', (short_code,)).fetchone() is not None:
            short_code = generate_short_code(length, allow_numbers, allow_special, allow_uppercase, allow_lowercase)

    if password:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
    else:
        password_hash = None

    conn.execute('INSERT INTO url_mapping (short_code, original_url, ip_address, expiry_time, password) VALUES (?, ?, ?, ?, ?)',
                 (short_code, original_url, ip_address, expiry_time, password_hash))
    conn.commit()
    conn.close()

    return redirect(url_for('index'))

@app.route('/<code>')
def redirect_to_url(code):
    conn = get_db_connection(DATABASE)
    url = conn.execute('SELECT original_url, click_count, expiry_time, password FROM url_mapping WHERE short_code = ?', (code,)).fetchone()

    if url:
        if url['expiry_time'] and datetime.datetime.now() > datetime.datetime.strptime(url['expiry_time'], '%Y-%m-%d %H:%M:%S'):
            conn.execute('DELETE FROM url_mapping WHERE short_code = ?', (code,))
            conn.execute('UPDATE api_tokens SET link_count = link_count - 1 WHERE token = (SELECT api_token FROM url_mapping WHERE short_code = ?)', (code,))
            conn.commit()
            conn.close()
            return 'URL has expired', 404

        if url['password']:
            return render_template('password.html', code=code)

        conn.execute('UPDATE url_mapping SET click_count = click_count + 1 WHERE short_code = ?', (code,))
        conn.execute('UPDATE api_tokens SET click_count = click_count + 1 WHERE token = (SELECT api_token FROM url_mapping WHERE short_code = ?)', (code,))
        conn.commit()
        conn.close()
        return redirect(url['original_url'])

    else:
        conn.close()
        return 'URL not found', 404

@app.route('/check_password', methods=['POST'])
def check_password():
    code = request.form['code']
    password = request.form['password']

    conn = get_db_connection(DATABASE)
    url = conn.execute('SELECT original_url, password FROM url_mapping WHERE short_code = ?', (code,)).fetchone()

    if url and url['password'] == hashlib.sha256(password.encode()).hexdigest():
        conn.execute('UPDATE url_mapping SET click_count = click_count + 1 WHERE short_code = ?', (code,))
        conn.execute('UPDATE api_tokens SET click_count = click_count + 1 WHERE token = (SELECT api_token FROM url_mapping WHERE short_code = ?)', (code,))
        conn.commit()
        conn.close()
        return redirect(url['original_url'])

    conn.close()
    return 'Incorrect password', 403

@app.route('/api/shorten', methods=['POST'])
@require_api_token
@limiter.limit("50 per minute")  # Rate limit for /api/shorten route
def api_shorten():
    data = request.json
    original_url = data.get('url')
    length = int(data.get('length', 6))
    allow_numbers = data.get('allow_numbers', True)
    allow_special = data.get('allow_special', False)
    allow_uppercase = data.get('allow_uppercase', True)
    allow_lowercase = data.get('allow_lowercase', True)
    expiry_time = data.get('expiry_time')

    if not is_valid_url(original_url):
        return 'Invalid URL', 400

    if is_blocked_domain(original_url):
        return 'Blocked domain', 400

    ip_address = request.remote_addr
    token = request.headers.get('Authorization')

    conn = get_db_connection(DATABASE)

    characters = ''
    if allow_numbers:
        characters += string.digits
    if allow_special:
        characters += string.punctuation
    if allow_uppercase:
        characters += string.ascii_uppercase
    if allow_lowercase:
        characters += string.ascii_lowercase

    if not characters:
        characters = string.ascii_letters + string.digits

    total_combinations = len(characters) ** length

    existing_codes_count = conn.execute('SELECT COUNT(*) FROM url_mapping').fetchone()[0]
    if existing_codes_count >= total_combinations:
        options_message = f"Length: {length}, Allow Numbers: {allow_numbers}, Allow Special: {allow_special}, Allow Uppercase: {allow_uppercase}, Allow Lowercase: {allow_lowercase}"
        return f'No other possible combination of {length} characters with the selected options is available. Selected options: {options_message}', 400

    short_code = generate_short_code(length, allow_numbers, allow_special, allow_uppercase, allow_lowercase)
    while conn.execute('SELECT 1 FROM url_mapping WHERE short_code = ?', (short_code,)).fetchone() is not None:
        short_code = generate_short_code(length, allow_numbers, allow_special, allow_uppercase, allow_lowercase)

    conn.execute('INSERT INTO url_mapping (short_code, original_url, ip_address, api_token, expiry_time) VALUES (?, ?, ?, ?, ?)',
                 (short_code, original_url, ip_address, token, expiry_time))
    conn.execute('UPDATE api_tokens SET link_count = link_count + 1 WHERE token = ?', (token,))
    conn.commit()
    conn.close()

    return {'short_code': short_code}, 201

@app.route('/api/generate_token', methods=['POST'])
def generate_token():
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

    conn = get_db_connection(DATABASE)
    conn.execute('INSERT INTO api_tokens (token) VALUES (?)', (token,))
    conn.commit()
    conn.close()

    return {'token': token}, 201

@app.route('/api/analytics', methods=['GET'])
@require_api_token
def api_analytics():
    token = request.headers.get('Authorization')
    conn = get_db_connection(DATABASE)

    api_data = conn.execute('SELECT link_count, click_count FROM api_tokens WHERE token = ?', (token,)).fetchone()
    links = conn.execute('SELECT short_code, original_url, click_count, expiry_time FROM url_mapping WHERE api_token = ?', (token,)).fetchall()

    analytics = {
        'link_count': api_data['link_count'],
        'click_count': api_data['click_count'],
        'links': [{'short_code': link['short_code'], 'original_url': link['original_url'], 'click_count': link['click_count'], 'expiry_time': link['expiry_time']} for link in links]
    }

    conn.close()
    return jsonify(analytics)

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
