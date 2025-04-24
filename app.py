from flask import Flask, render_template, request, redirect, session, url_for
from flask_socketio import SocketIO, emit
from flask import request as socket_request  # <-- Corrected import
from werkzeug.security import generate_password_hash, check_password_hash
import os, sqlite3

app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app)

DB = "users.db"
connected_users = {}

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )""")
    conn.commit()
    conn.close()

init_db()

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
    return render_template('index.html', username=current_user, users=other_users)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        username = session['username']

        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username=?", (username,))
        row = c.fetchone()

        if row and check_password_hash(row[0], old_password):
            new_hashed = generate_password_hash(new_password)
            c.execute("UPDATE users SET password=? WHERE username=?", (new_hashed, username))
            conn.commit()
            conn.close()
            return "✅ Password changed successfully! <a href='/chat'>Go back to chat</a>"
        else:
            conn.close()
            return "❌ Incorrect old password. <a href='/change_password'>Try again</a>"

    return render_template('change_password.html', username=session['username'])


def get_all_usernames():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT username FROM users")
    usernames = [row[0] for row in c.fetchall()]
    conn.close()
    return usernames

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
    emit('message', data, broadcast=True)

@socketio.on('private_message')
def handle_private_message(data):
    recipient = data.get('to')
    sender = session.get('username')
    if recipient and recipient in connected_users:
        sid = connected_users[recipient]
        emit('private_message', {'user': sender, 'text': data['text'], 'to': recipient}, room=sid)
        emit('private_message', {'user': sender, 'text': data['text'], 'to': recipient}, room=socket_request.sid)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=10000)
