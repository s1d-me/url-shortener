from flask import Flask, request, redirect, url_for, render_template
import string
import random
import sqlite3
import os
from functools import wraps

app = Flask(__name__)

DATABASE = 'url_shortener.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        conn = get_db_connection()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS url_mapping (
                short_code TEXT PRIMARY KEY,
                original_url TEXT,
                ip_address TEXT,
                click_count INTEGER DEFAULT 0
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS api_tokens (
                token TEXT PRIMARY KEY
            )
        ''')
        conn.commit()
        conn.close()

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

        conn = get_db_connection()
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
    conn = get_db_connection()
    urls = conn.execute('SELECT * FROM url_mapping').fetchall()
    conn.close()

    return render_template('gen.html', urls=urls)

@app.route('/shorten', methods=['POST'])
def shorten():
    original_url = request.form['url']
    custom_code = request.form.get('custom_code')

    length = int(request.form['length'])
    allow_numbers = 'allow_numbers' in request.form
    allow_special = 'allow_special' in request.form
    allow_uppercase = 'allow_uppercase' in request.form
    allow_lowercase = 'allow_lowercase' in request.form

    ip_address = request.remote_addr

    conn = get_db_connection()

    if custom_code:
        short_code = custom_code
        if conn.execute('SELECT 1 FROM url_mapping WHERE short_code = ?', (short_code,)).fetchone() is not None:
            return 'Custom code already exists. Please choose another one.', 400
    else:
        short_code = generate_short_code(length, allow_numbers, allow_special, allow_uppercase, allow_lowercase)
        while conn.execute('SELECT 1 FROM url_mapping WHERE short_code = ?', (short_code,)).fetchone() is not None:
            short_code = generate_short_code(length, allow_numbers, allow_special, allow_uppercase, allow_lowercase)

    conn.execute('INSERT INTO url_mapping (short_code, original_url, ip_address) VALUES (?, ?, ?)', (short_code, original_url, ip_address))
    conn.commit()
    conn.close()

    return redirect(url_for('index'))

@app.route('/<code>')
def redirect_to_url(code):
    conn = get_db_connection()
    url = conn.execute('SELECT original_url, click_count FROM url_mapping WHERE short_code = ?', (code,)).fetchone()

    if url:
        conn.execute('UPDATE url_mapping SET click_count = click_count + 1 WHERE short_code = ?', (code,))
        conn.commit()
        conn.close()
        return redirect(url['original_url'])

    else:
        conn.close()
        return 'URL not found', 404

@app.route('/api/shorten', methods=['POST'])
@require_api_token
def api_shorten():
    data = request.json
    original_url = data.get('url')
    length = int(data.get('length', 6))
    allow_numbers = data.get('allow_numbers', True)
    allow_special = data.get('allow_special', False)
    allow_uppercase = data.get('allow_uppercase', True)
    allow_lowercase = data.get('allow_lowercase', True)

    ip_address = request.remote_addr

    conn = get_db_connection()

    short_code = generate_short_code(length, allow_numbers, allow_special, allow_uppercase, allow_lowercase)
    while conn.execute('SELECT 1 FROM url_mapping WHERE short_code = ?', (short_code,)).fetchone() is not None:
        short_code = generate_short_code(length, allow_numbers, allow_special, allow_uppercase, allow_lowercase)

    conn.execute('INSERT INTO url_mapping (short_code, original_url, ip_address) VALUES (?, ?, ?)', (short_code, original_url, ip_address))
    conn.commit()
    conn.close()

    return {'short_code': short_code}, 201

@app.route('/api/generate_token', methods=['POST'])
def generate_token():
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

    conn = get_db_connection()
    conn.execute('INSERT INTO api_tokens (token) VALUES (?)', (token,))
    conn.commit()
    conn.close()

    return {'token': token}, 201

if __name__ == '__main__':
    init_db()
    # port = int(os.getenv('PORT'))
    app.run(debug=True, host='0.0.0.0', port=5000)