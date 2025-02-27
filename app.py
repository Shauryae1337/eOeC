from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this in production
socketio = SocketIO(app)

# Store active clients and their public keys
active_clients = {}

@app.route('/')
def index():
    return render_template('chat.html')

@socketio.on('connect')
def handle_connect():
    """Handle new client connections"""
    active_clients[request.sid] = None  # Initialize client entry
    emit('connected', {'message': 'Connected to chat'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnections"""
    if request.sid in active_clients:
        del active_clients[request.sid]

@socketio.on('generate_keys')
def handle_key_generation():
    """Generate RSA key pair for client"""
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )
    
    # Store public key for this client
    active_clients[request.sid] = public_key
    
    emit('keys_generated', {
        'private_key': base64.b64encode(private_key).decode('utf-8'),
        'public_key': base64.b64encode(public_key).decode('utf-8')
    })

@socketio.on('message')
def handle_message(data):
    """Handle encrypted messages"""
    sender_sid = request.sid
    recipient_sid = data['recipient']
    
    if recipient_sid in active_clients:
        emit('message', {
            'sender': request.sid,
            'content': data['content'],
            'timestamp': data['timestamp']
        }, room=recipient_sid)
    else:
        emit('error', {'message': 'Recipient not found'})

if __name__ == '__main__':
    socketio.run(app, host='localhost', port=5000)
