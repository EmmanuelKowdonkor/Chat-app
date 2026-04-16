from flask import Flask, render_template, request, redirect, session, url_for
from flask_socketio import SocketIO, emit
from flask import request as socket_request
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "your_super_secret_fixed_key_123"
socketio = SocketIO(app, cors_allowed_origins="*")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, "users.db")

connected_users = {}
active_calls = {}  # call_id -> {"caller": ..., "callee": ..., "type": "audio"/"video"}


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

    return render_template(
        'index.html',
        username=current_user,
        users=other_users,
        history=history
    )


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
        emit("user_connected", {"user": username}, broadcast=True)


@socketio.on('disconnect')
def handle_disconnect():
    username = session.get('username')
    if username and username in connected_users:
        del connected_users[username]
        emit("user_disconnected", {"user": username}, broadcast=True)


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


# ----------------------------
# CALL SIGNALING
# ----------------------------

@socketio.on("start_call")
def start_call(data):
    caller = session.get("username")
    callee = data.get("to")
    call_type = data.get("call_type")  # "audio" or "video"
    call_id = data.get("call_id")

    if not caller or not callee or callee == "group" or call_type not in ["audio", "video"] or not call_id:
        emit("call_error", {"message": "Invalid call request."}, room=socket_request.sid)
        return

    if callee not in connected_users:
        emit("call_unavailable", {"to": callee, "message": f"{callee} is offline."}, room=socket_request.sid)
        return

    active_calls[call_id] = {
        "caller": caller,
        "callee": callee,
        "type": call_type
    }

    emit("incoming_call", {
        "call_id": call_id,
        "from": caller,
        "call_type": call_type
    }, room=connected_users[callee])

@socketio.on("accept_call")
def accept_call(data):
    username = session.get("username")
    call_id = data.get("call_id")

    call = active_calls.get(call_id)
    if not username or not call:
        return

    caller = call["caller"]
    callee = call["callee"]

    if username != callee:
        return

    call["accepted"] = True

    if caller in connected_users:
        emit("call_accepted", {
            "call_id": call_id,
            "by": callee,
            "call_type": call["type"]
        }, room=connected_users[caller])


@socketio.on("reject_call")
def reject_call(data):
    username = session.get("username")
    call_id = data.get("call_id")

    call = active_calls.get(call_id)
    if not username or not call:
        return

    caller = call["caller"]
    callee = call["callee"]

    if username != callee:
        return

    if caller in connected_users:
        emit("call_rejected", {
            "call_id": call_id,
            "by": callee
        }, room=connected_users[caller])

    active_calls.pop(call_id, None)
    

@socketio.on("end_call")
def end_call(data):
    username = session.get("username")
    call_id = data.get("call_id")

    call = active_calls.get(call_id)
    if not username or not call:
        return

    caller = call["caller"]
    callee = call["callee"]
    call_type = call["type"]
    accepted = call.get("accepted", False)

    other = callee if username == caller else caller

    # Notify the other side that the call ended
    if other in connected_users:
        emit("call_ended", {
            "call_id": call_id,
            "by": username,
            "accepted": accepted
        }, room=connected_users[other])

    # If caller ended before callee accepted, create missed call message for callee
    if not accepted and username == caller:
        missed_text = f"Missed {call_type} call from {caller}"

        save_message(caller, callee, missed_text)

        missed_message = {
            "user": caller,
            "text": missed_text,
            "to": callee,
            "missed_call": True
        }

        if callee in connected_users:
            emit("private_message", missed_message, room=connected_users[callee])

    active_calls.pop(call_id, None)


@socketio.on("webrtc_offer")
def webrtc_offer(data):
    username = session.get("username")
    to_user = data.get("to")
    offer = data.get("offer")
    call_id = data.get("call_id")

    if not username or not to_user or not offer or not call_id:
        return

    if to_user in connected_users:
        emit("webrtc_offer", {
            "from": username,
            "offer": offer,
            "call_id": call_id
        }, room=connected_users[to_user])


@socketio.on("webrtc_answer")
def webrtc_answer(data):
    username = session.get("username")
    to_user = data.get("to")
    answer = data.get("answer")
    call_id = data.get("call_id")

    if not username or not to_user or not answer or not call_id:
        return

    if to_user in connected_users:
        emit("webrtc_answer", {
            "from": username,
            "answer": answer,
            "call_id": call_id
        }, room=connected_users[to_user])


@socketio.on("ice_candidate")
def ice_candidate(data):
    username = session.get("username")
    to_user = data.get("to")
    candidate = data.get("candidate")
    call_id = data.get("call_id")

    if not username or not to_user or candidate is None or not call_id:
        return

    if to_user in connected_users:
        emit("ice_candidate", {
            "from": username,
            "candidate": candidate,
            "call_id": call_id
        }, room=connected_users[to_user])


@socketio.on("request_video_upgrade")
def request_video_upgrade(data):
    username = session.get("username")
    to_user = data.get("to")
    call_id = data.get("call_id")

    if not username or not to_user or not call_id:
        return

    if to_user in connected_users:
        emit("video_upgrade_requested", {
            "from": username,
            "call_id": call_id
        }, room=connected_users[to_user])


@socketio.on("accept_video_upgrade")
def accept_video_upgrade(data):
    username = session.get("username")
    to_user = data.get("to")
    call_id = data.get("call_id")

    if not username or not to_user or not call_id:
        return

    if to_user in connected_users:
        emit("video_upgrade_accepted", {
            "from": username,
            "call_id": call_id
        }, room=connected_users[to_user])


@socketio.on("reject_video_upgrade")
def reject_video_upgrade(data):
    username = session.get("username")
    to_user = data.get("to")
    call_id = data.get("call_id")

    if not username or not to_user or not call_id:
        return

    if to_user in connected_users:
        emit("video_upgrade_rejected", {
            "from": username,
            "call_id": call_id
        }, room=connected_users[to_user])


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=10000)