from flask import Flask, request, redirect, url_for, render_template #imports flasks
import string # abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890
import random # asdkljfkdajfklapqopqioi099-34939043nncbmz,n,m.,1i9238192.,X,MAOJWRU9Q0
import sqlite3 #imports sqlite, our database manager
import os #imports os, for environment variables and weird shit, also because HEROKU

app = Flask(__name__) #flask init

DATABASE = 'url_shortener.db' #sqlite init

def get_db_connection(): #connects to the database, configures data as dictionary
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(): #inits the database, creates "url_mapping" table if it doesn't exist
    with app.app_context():
        conn = get_db_connection()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS url_mapping (
                short_code TEXT PRIMARY KEY,
                original_url TEXT,
                ip_address TEXT,
                click_count INTEGER DEFAULT 0
            )
        ''') #the table now has 4 columns, short code refers to the short code generated,
        # original url refers to the original url which was shortened and links to the short code,
        # ip address refers to the ip address of the user who created the short code
        # click count refers to the number of times the short code has been clicked
        # we're adding analytics now babyy
        conn.commit()
        conn.close()

#this code checks for input values and generates a short code based on the request and parameters
def generate_short_code(length, allow_numbers, allow_special, allow_uppercase, allow_lowercase):
    characters = ''

    if allow_numbers: #checks if the user wants numbers
        characters += string.digits

    if allow_special: #checks if the user allows special character
        characters += string.punctuation

    if allow_uppercase: #checks if user wants uppercase char
        characters += string.ascii_uppercase

    if allow_lowercase: #checks for lower case char
        characters += string.ascii_lowercase

    if not characters: # if none are selected
        characters = string.ascii_letters + string.digits  # Default to letters and digits, capital

    return ''.join(random.choice(characters) for _ in range(length))

@app.route('/') #home page route
# retreives all existing url mapping from the database
# constructs an html table with this mapping for better debugging
# renders the html with options to generate short code lmao
def index():
    conn = get_db_connection() #establishes a connection with db
    urls = conn.execute('SELECT * FROM url_mapping').fetchall() #fetching the URL mapping table
    #stores all rows into 'urls'
    conn.close() #close the connections cuz we've had enough

    return render_template('index.html', urls=urls) #renders the template with the urls data

@app.route('/shorten', methods=['POST']) #new route 'shorten', basically shortens the url provided in the main page

def shorten(): # shorts the original url based on parameters
    original_url = request.form['url'] #original url is saved because we need it to link it to the shortened url
    custom_code = request.form.get('custom_code') # checks if any custom code was entered, if yes, then we don't proceed with randomizing

    length = int(request.form['length']) #fetches for the max length of chars wanted
    #fetches for the parameters
    allow_numbers = 'allow_numbers' in request.form
    allow_special = 'allow_special' in request.form
    allow_uppercase = 'allow_uppercase' in request.form
    allow_lowercase = 'allow_lowercase' in request.form

    # fetches for the IP address of the person shortening the email
    ip_address = request.remote_addr

    conn = get_db_connection() #connects with the beautiful database again

    if custom_code: #checks if custom code was provided
        short_code = custom_code
        if conn.execute('SELECT 1 FROM url_mapping WHERE short_code = ?', (short_code,)).fetchone() is not None:
            return 'Custom code already exists. Please choose another one.', 400 #generates a 400 if code already exists
    else: # apparently no custom code was provided, it generates a random short code until it finds a unique one
        short_code = generate_short_code(length, allow_numbers, allow_special, allow_uppercase, allow_lowercase)
        while conn.execute('SELECT 1 FROM url_mapping WHERE short_code = ?', (short_code,)).fetchone() is not None:
            short_code = generate_short_code(length, allow_numbers, allow_special, allow_uppercase, allow_lowercase)

    conn.execute('INSERT INTO url_mapping (short_code, original_url, ip_address) VALUES (?, ?, ?)', (short_code, original_url, ip_address)) #stores the generated short code, original url and user's IP in the database
    conn.commit()
    conn.close() # closes the connection again
    # can't really establish a connection with the database for long enough
    # just like how i can't emotionally and socially establish a connection with society

    return redirect(url_for('index')) # redirects user back to the home page

@app.route('/<code>') # handles shortened URLs, redirects them to the original link

def redirect_to_url(code):

    conn = get_db_connection() # connects with the database again. oh god
    url = conn.execute('SELECT original_url, click_count FROM url_mapping WHERE short_code = ?', (code,)).fetchone() # fetches the short code from the url path and asks the database if the database has seen it somewhere

    if url: # if url is found (the database knows)
        conn.execute('UPDATE url_mapping SET click_count = click_count + 1 WHERE short_code = ?', (code,))  # click count of the url increases by one
        conn.commit() # commits to the database
        conn.close() # closes the connection with the database, again
        return redirect(url['original_url']) # redirects the user to the original url, meow

    else: # if url is not found (the database DOES NOT know)
        conn.close() # closes the connection nevertheless
        return 'URL not found', 404 # returns a 404 and lets the user know that the url was not found

if __name__ == '__main__': # runs the app because that's actually the main motive
    init_db() # initializes the database (it's actually a function)
    port = int(os.getenv('PORT'))
    app.run(debug=True, host='0.0.0.0', port=port) # runs the flask app we defined earlier (probably the first line after imports)