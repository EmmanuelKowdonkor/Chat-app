from flask import Flask, render_template, request, redirect, session, url_for
from flask_socketio import SocketIO, emit
from flask import request as socket_request
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "your_super_secret_fixed_key_123"
socketio = SocketIO(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, "users.db")

connected_users = {}

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()

init_db()

def get_all_usernames():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT username FROM users")
    usernames = [row[0] for row in c.fetchall()]
    conn.close()
    return usernames

def save_message(sender, recipient, content):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute(
        "INSERT INTO messages (sender, recipient, content) VALUES (?, ?, ?)",
        (sender, recipient, content)
    )
    conn.commit()
    conn.close()

def load_user_history(current_user):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
        SELECT sender, recipient, content
        FROM messages
        WHERE recipient = 'group'
           OR sender = ?
           OR recipient = ?
        ORDER BY timestamp ASC
    """, (current_user, current_user))
    history = [{"user": row[0], "to": row[1], "text": row[2]} for row in c.fetchall()]
    conn.close()
    return history

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()

        if row and check_password_hash(row[0], password):
            session['username'] = username
            return redirect(url_for('chat'))
        else:
            return "Invalid credentials. <a href='/'>Try again</a>"

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        try:
            conn = sqlite3.connect(DB)
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "Username already taken. <a href='/register'>Try another</a>"

    return render_template('register.html')

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = session['username']
    all_users = get_all_usernames()
    other_users = [u for u in all_users if u != current_user]
    history = load_user_history(current_user)

    return render_template('index.html', username=current_user, users=other_users, history=history)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']

        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username=?", (username,))
        row = c.fetchone()

        if row:
            hashed = generate_password_hash(new_password)
            c.execute("UPDATE users SET password=? WHERE username=?", (hashed, username))
            conn.commit()
            conn.close()
            return "✅ Password reset successfully. <a href='/'>Login</a>"
        else:
            conn.close()
            return "❌ Username not found. <a href='/forgot-password'>Try again</a>"

    return render_template('forgot_password.html')

@socketio.on('connect')
def handle_connect():
    username = session.get('username')
    if username:
        connected_users[username] = socket_request.sid

@socketio.on('disconnect')
def handle_disconnect():
    username = session.get('username')
    if username and username in connected_users:
        del connected_users[username]

@socketio.on('message')
def handle_group_message(data):
    sender = session.get('username')
    text = data.get('text')

    if not sender or not text:
        return

    message_data = {
        'user': sender,
        'text': text,
        'to': 'group'
    }

    save_message(sender, 'group', text)
    emit('message', message_data, broadcast=True)

@socketio.on('private_message')
def handle_private_message(data):
    recipient = data.get('to')
    sender = session.get('username')
    text = data.get('text')

    if not sender or not recipient or not text:
        return

    message_data = {
        'user': sender,
        'text': text,
        'to': recipient
    }

    save_message(sender, recipient, text)

    if recipient in connected_users:
        emit('private_message', message_data, room=connected_users[recipient])

    emit('private_message', message_data, room=socket_request.sid)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=10000)