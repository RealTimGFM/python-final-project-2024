from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from datetime import datetime
import sqlite3
import os
import matplotlib.pyplot as plt
import io
import base64
import bcrypt
from functools import wraps
from flask import request, jsonify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# Initialize Flask app
app = Flask(__name__)

# Generate a cryptographically secure secret key
salt = os.urandom(16)  # Random salt
password = b"passwd" 
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(password)

# Set the derived key as the Flask secret_key
app.secret_key = key.hex()

# Database setup
DB_PATH = 'atm_database.db'
#check IP blocked 
BLOCKED_IPS = {'127.0.0.9'} #change to .1 if want to be blocked
def check_ip(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.remote_addr in BLOCKED_IPS:
            return jsonify({'error': 'blocked'}), 403  
        return f(*args, **kwargs) 
    return wrapper

def init_db():
    """Initialize the database and create necessary tables if they don't exist."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(''' 
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL, 
                balance REAL DEFAULT 0.0
            )
        ''')
        cursor.execute(''' 
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                amount REAL,
                type TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

@app.before_first_request
def setup():
    """Initialize the database on the first request."""
    if not os.path.exists(DB_PATH):
        init_db()

@app.route('/')
def index():
    return redirect(url_for('login'))

#show secret key
@app.route('/show_secret_key')
def show_secret_key():
    # For testing purposes, showing the secret key
    return f'Secure secret key is: {app.secret_key}'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):  # user[2] contains the hashed password
                session['user_id'] = user[0]
                return redirect(url_for('main'))
            else:
                flash('Invalid credentials', 'error')
                
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Generate a salt and hash the password
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
                conn.commit()
                flash('Account created successfully! Please log in.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Username already exists', 'error')
    return render_template('signup.html')

@app.route('/main')
@check_ip
def main():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
        balance = cursor.fetchone()[0]

    return render_template('main.html', balance=balance)
#Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))
# Withdraw route
@app.route('/withdraw', methods=['POST'])
def withdraw():
    if 'user_id' not in session:
        return redirect(url_for('login'))    
    amount = float(request.form['amount'])    
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        # Retrieve current balance
        cursor.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
        balance = cursor.fetchone()[0]
        
        if amount > balance:
            flash("Insufficient balance", "error") 
        else:
            # Proceed with withdrawal
            new_balance = balance - amount
            cursor.execute('UPDATE users SET balance = ? WHERE id = ?', (new_balance, session['user_id']))
            cursor.execute('INSERT INTO transactions (user_id, amount, type) VALUES (?, ?, ?)', 
                           (session['user_id'], -amount, 'withdrawal'))
            conn.commit()
            flash("Withdrawal successful", "success")  # Use category "success" for success messages
    
    return redirect(url_for('main'))

# Deposit route
@app.route('/deposit', methods=['POST'])
def deposit():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    amount = float(request.form['amount'])
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        # Update balance and record transaction
        cursor.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
        balance = cursor.fetchone()[0]
        
        new_balance = balance + amount
        cursor.execute('UPDATE users SET balance = ? WHERE id = ?', (new_balance, session['user_id']))
        cursor.execute('INSERT INTO transactions (user_id, amount, type) VALUES (?, ?, ?)', 
                       (session['user_id'], amount, 'deposit'))
        conn.commit()
        flash("Deposit successful")
    return redirect(url_for('main'))

# Graph route
@app.route('/graph')
def graph():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Retrieve transactions for the current user
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT amount, timestamp FROM transactions WHERE user_id = ? ORDER BY timestamp', 
                       (session['user_id'],))
        transactions = cursor.fetchall()

    # Prepare data for the graph
    formatted_dates = [datetime.strptime(t[1], '%Y-%m-%d %H:%M:%S').date().strftime('%Y-%m-%d') for t in transactions]
    amounts = [t[0] for t in transactions]
    cumulative_balance = []
    balance = 0
    for amount in amounts:
        balance += amount
        cumulative_balance.append(balance)
        
    # Generate graph
    plt.figure(figsize=(14, 7))
    plt.plot(formatted_dates, cumulative_balance, marker='o')
    plt.xlabel('Date')
    plt.ylabel('Balance')
    plt.title('Spending History')
    plt.xticks(rotation=45)

    # Save graph to a byte buffer (like a memory)
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    plt.close()
    
    # Convert graph to base64 and send to the page
    img_data = base64.b64encode(buf.getvalue()).decode('utf-8')
    return render_template('graph.html', img_data=img_data)

if __name__ == '__main__':
    app.run(debug=True)
