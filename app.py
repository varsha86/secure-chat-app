from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit, join_room
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

users = {}
keys = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')

    if username in users:
        return jsonify({'message': 'User already exists'}), 400

    salt = get_random_bytes(16)
    key = scrypt(password, salt, 32, N=2**14, r=8, p=1)
    users[username] = {'salt': base64.b64encode(salt).decode(), 'key': base64.b64encode(key).decode()}
    return jsonify({'message': 'User registered successfully'})

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    if username not in users:
        return jsonify({'message': 'Invalid username or password'}), 400

    salt = base64.b64decode(users[username]['salt'])
    key = scrypt(password, salt, 32, N=2**14, r=8, p=1)

    if base64.b64encode(key).decode() != users[username]['key']:
        return jsonify({'message': 'Invalid username or password'}), 400

    keys[username] = key
    return jsonify({'message': 'Login successful'})

@socketio.on('message')
def handle_message(data):
    sender = data['sender']
    recipient = data['recipient']
    message = data['message']

    if recipient not in keys:
        emit('error', {'message': 'Recipient not found'})
        return

    recipient_key = keys[recipient]

    cipher = AES.new(recipient_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())

    encrypted_message = {
        'nonce': base64.b64encode(cipher.nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'tag': base64.b64encode(tag).decode()
    }

    emit('receive_message', encrypted_message, room=recipient)

@socketio.on('join')
def on_join(data):
    username = data['username']
    join_room(username)

if __name__ == '__main__':
    socketio.run(app, debug=True)
