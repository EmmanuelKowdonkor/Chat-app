from flask import Flask, render_template, request, redirect, session, url_for
from flask_socketio import SocketIO, emit, request as socket_request
from werkzeug.security import generate_password_hash, check_password_hash
import os, sqlite3

app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app)

DB = "users.db"
users = {}  # username: sid

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL
              )""")
    c.execute("""CREATE TABLE IF NOT EXISTS messages (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  sender TEXT NOT NULL,
                  receiver TEXT,
                  content TEXT NOT NULL,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
              )""")
    conn.commit()
    conn.close()

def save_message(sender, receiver, content):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("INSERT INTO messages (sender, receiver, content) VALUES (?, ?, ?)",
              (sender, receiver, content))
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
    other_users = [user for user in users.keys() if user != current_user]
    return render_template('index.html', username=current_user, users=other_users)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@socketio.on('connect')
def handle_connect():
    username = session.get('username')
    if username:
        users[username] = socket_request.sid

@socketio.on('disconnect')
def handle_disconnect():
    disconnected_sid = socket_request.sid
    for user, sid in list(users.items()):
        if sid == disconnected_sid:
            del users[user]
            break

@socketio.on('message')
def handle_group_message(data):
    sender = data['user']
    content = data['text']
    save_message(sender, None, content)
    emit('message', data, broadcast=True)

@socketio.on('private_message')
def handle_private_message(data):
    sender = session.get('username')
    receiver = data.get('to')
    content = data.get('text')
    save_message(sender, receiver, content)
    if receiver in users:
        emit('private_message', {'user': sender, 'text': content}, room=users[receiver])
    emit('private_message', {'user': sender, 'text': content}, room=socket_request.sid)

@socketio.on('call')
def handle_call(data):
    data['username'] = session.get('username')
    emit('call', data, broadcast=True, include_self=False)

@socketio.on('answer')
def handle_answer(data):
    data['username'] = session.get('username')
    emit('answer', data, broadcast=True, include_self=False)

@socketio.on('ice-candidate')
def handle_ice(data):
    emit('ice-candidate', data, broadcast=True, include_self=False)

if __name__ == '__main__':
   socketio.run(app, host='0.0.0.0', port=10000)
