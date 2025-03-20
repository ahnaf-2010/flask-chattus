from flask import Flask, render_template, request, redirect, url_for, send_from_directory, jsonify
from flask_socketio import SocketIO, join_room, leave_room, emit
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import random
import string
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chattus.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024  # 2GB file upload limit
app.config['REMEMBER_COOKIE_DURATION'] = 86400 * 30  # Keep user logged in for 30 days
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app, cors_allowed_origins="*")
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Ensure uploads folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Server Model
class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(6), unique=True, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# Message Model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('server.id'), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)

# File Model
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('server.id'), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    filename = db.Column(db.String(255), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return "Username and password are required", 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=True)  # Keep user logged in
            return redirect(url_for('dashboard'))
        return "Invalid credentials", 401

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user_servers = Server.query.filter_by(owner_id=current_user.id).all()

    if request.method == 'POST':
        action = request.form.get('action')

        if action == "create":
            server_name = request.form.get('server_name')
            if not server_name:
                return jsonify({"error": "Server name is required"}), 400

            server_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
            new_server = Server(name=server_name, code=server_code, owner_id=current_user.id)
            db.session.add(new_server)
            db.session.commit()

            return jsonify({"server_code": server_code}), 200  # Return code for UI

        elif action == "join":
            server_code = request.form.get('server_code')
            server = Server.query.filter_by(code=server_code).first()
            if server:
                return redirect(url_for('chat', code=server_code))
            return "Invalid server code", 400

    return render_template('dashboard.html', user_servers=user_servers)

@app.route('/chat/<code>', methods=['GET'])
@login_required
def chat(code):
    server = Server.query.filter_by(code=code).first()
    if not server:
        return "Server Not Found", 404

    messages = Message.query.filter_by(server_id=server.id).all()
    files = File.query.filter_by(server_id=server.id).all()

    return render_template('chat.html', server=server, username=current_user.username, messages=messages, files=files)

@app.route('/upload/<code>', methods=['POST'])
@login_required
def upload_file(code):
    server = Server.query.filter_by(code=code).first()
    if not server:
        return "Server Not Found", 404

    file = request.files.get('file')
    if not file or file.filename == '':
        return "No file selected", 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    new_file = File(server_id=server.id, username=current_user.username, filename=filename)
    db.session.add(new_file)
    db.session.commit()

    emit('file_uploaded', {
        'username': current_user.username,
        'filename': filename,
        'file_url': url_for('uploaded_file', filename=filename)
    }, room=code, namespace='/')

    return redirect(url_for('chat', code=code))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@socketio.on('join')
def handle_join(data):
    username = data.get('username')
    room = data.get('room')

    if username and room:
        join_room(room)
        emit('message', {'msg': f"{username} joined the chat!", 'username': 'System'}, room=room)

@socketio.on('leave')
def handle_leave(data):
    username = data.get('username')
    room = data.get('room')

    if username and room:
        leave_room(room)
        emit('message', {'msg': f"{username} has left the chat.", 'username': 'System'}, room=room)

@socketio.on('message')
def handle_message(data):
    username = data.get('username')
    room = data.get('room')
    msg = data.get('msg')

    server = Server.query.filter_by(code=room).first()
    if server and username and msg:
        new_message = Message(server_id=server.id, username=username, message=msg)
        db.session.add(new_message)
        db.session.commit()

        emit('message', {'msg': msg, 'username': username}, room=room)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, host='0.0.0.0', port=5000)
