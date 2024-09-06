from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Required for flash messages
basedir = os.path.abspath(os.path.dirname(__file__))  # Get the directory of the current file
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "instance", "users.db")}'
db = SQLAlchemy(app)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    devices = db.relationship('Device', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'
    
    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(120), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)

    def __repr__(self):
        return f'<Device {self.device_id}>'

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)

    def __repr__(self):
        return f'<Attendance {self.username} at {self.timestamp}>'

# Create the database tables
with app.app_context():
    db.create_all()

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0]
    else:
        ip = request.remote_addr
    return ip

# Example function to check if IP is within the allowed range
def is_valid_ip(ip):
    print(ip)
    # Replace this with your college's IP range
    allowed_ip_ranges = ['192.168.1.', '103.65.202.', '127.0.0.']  # Example ranges
    return any(ip.startswith(range_prefix) for range_prefix in allowed_ip_ranges)

# Define the bounds of the college area (latitude and longitude in degrees)
COLLEGE_LAT_MIN = 12.9716  # Example minimum latitude
COLLEGE_LAT_MAX = 12.9820  # Example maximum latitude
COLLEGE_LON_MIN = 77.5946  # Example minimum longitude
COLLEGE_LON_MAX = 77.6060  # Example maximum longitude

def is_within_college_area(lat, lon):
    return COLLEGE_LAT_MIN <= lat <= COLLEGE_LAT_MAX and COLLEGE_LON_MIN <= lon <= COLLEGE_LON_MAX

# Home Route
@app.route('/')
def home():
    return redirect(url_for('login'))

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        userName = request.form['username'].strip()
        passWord = request.form['password'].strip()

        # Get client IP and validate
        ip = get_client_ip()
        if not is_valid_ip(ip):
            flash("Access denied. Not connected to the college network.")
            return redirect(url_for('login'))

        # Query the database for the user
        userM = User.query.filter_by(username=userName).first()

        if userM and userM.check_password(passWord):
            return f"Welcome {userName}!"
        else:
            flash("Invalid Credentials, Please try again.")
            return redirect(url_for('login'))

    return render_template('login.html')

# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        if User.query.filter_by(username=username).first():
            flash("Username already exists.")
            return redirect(url_for('register'))

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash("User registered successfully!")
        return redirect(url_for('login'))

    return render_template('register.html')

# Device Registration Route
@app.route('/register_device', methods=['POST'])
def register_device():
    username = request.form['username'].strip()
    device_id = request.form['device_id'].strip()
    latitude = float(request.form['latitude'])
    longitude = float(request.form['longitude'])

    if not is_within_college_area(latitude, longitude):
        flash("Device location is outside the college area.")
        return redirect(url_for('register_device'))

    user = User.query.filter_by(username=username).first()
    if user:
        # Register the device
        new_device = Device(device_id=device_id, user=user, latitude=latitude, longitude=longitude)
        db.session.add(new_device)
        db.session.commit()
        flash("Device registered successfully!")
        return redirect(url_for('login'))
    else:
        flash("Invalid Username.")
        return redirect(url_for('register_device'))

# Scan Route
@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        qr_code_data = request.form['qr_code_data'].strip()
        username = request.form['username'].strip()
        device_id = request.form['device_id'].strip()
        latitude = float(request.form['latitude'])
        longitude = float(request.form['longitude'])

        # Get client IP and validate
        ip = get_client_ip()
        if not is_valid_ip(ip):
            flash("Access denied. Not connected to the college network.")
            return redirect(url_for('scan'))

        if not is_within_college_area(latitude, longitude):
            flash("Attendance location is outside the college area.")
            return redirect(url_for('scan'))

        # Validate device
        user = User.query.filter_by(username=username).first()
        device = Device.query.filter_by(device_id=device_id, user=user).first()
        if user and device:
            if qr_code_data == "attendance_session_001":
                # Mark attendance
                attendance = Attendance(username=username, latitude=latitude, longitude=longitude)
                db.session.add(attendance)
                db.session.commit()
                return f"Attendance recorded for {username}!"
            else:
                flash("Invalid QR Code Data.")
        else:
            flash("Invalid Device or Username.")
        return redirect(url_for('scan'))

    return render_template('scan.html')

@app.route('/view_qr')
def view_qr():
    return render_template('view_qr.html')

@app.route('/view_attendance')
def view_attendance():
    records = Attendance.query.all()
    return render_template('view_attendance.html', records=records)

if __name__ == '__main__':
    app.run(debug=True)