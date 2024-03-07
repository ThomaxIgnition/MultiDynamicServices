from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import os
import traceback

app = Flask(__name__, static_url_path='/static', static_folder='static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///real_estate.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.secret_key = 'blues4life'
app.debug = True  # Enable debug mode
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(100), nullable=False)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

class Apartment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    media = db.relationship('Media', backref='apartment', lazy=True)
    # Define other columns as needed

class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    # Define other columns as needed

class Media(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    alt = db.Column(db.String(255))
    title = db.Column(db.String(255))
    apartment_id = db.Column(db.Integer, db.ForeignKey('apartment.id'), nullable=False)

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

with app.app_context():
    db.create_all()
    # Create the admin user if it doesn't exist
    admin = Admin.query.filter_by(username='Thomax').first()
    if not admin:
        admin = Admin(username='Thomax')
        admin.set_password('blues4life')  # Set the password
        db.session.add(admin)
        db.session.commit()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/real_estate')
def real_estate():
    try:
        locations = Location.query.all()
        return render_template('real_estate.html', locations=locations)
    except Exception as e:
        traceback.print_exc()
        return str(e), 500

@app.route('/locations')
def get_locations():
    locations = Location.query.all()
    return jsonify(locations)

@app.route('/apartments/<int:location_id>')
def get_apartments(location_id):
    apartments = Apartment.query.filter_by(location_id=location_id).all()
    return jsonify(apartments)

@app.route('/upload_media', methods=['POST'])
@login_required
def upload_media():
    if request.method == 'POST':
        file = request.files['file']
        apartment_id = request.form.get('apartment_id')  # Get the apartment ID from the form
        if file and apartment_id:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            # Save file information to the database
            media = Media(filename=filename, apartment_id=apartment_id)
            db.session.add(media)
            db.session.commit()
            return 'File uploaded successfully!'
    return 'Upload failed!'

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'Thomax' and password == 'blues4life':
            # Login successful, redirect to admin dashboard
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password.')
            return render_template('admin_login.html')
    return render_template('admin_login.html')

@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            # Save file information to the database
            media = Media(filename=filename)
            db.session.add(media)
            db.session.commit()
            flash('File uploaded successfully!')
        else:
            flash('No file selected!')

    medias = Media.query.all()
    return render_template('admin_dashboard.html', medias=medias)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'thomax' and password == 'blues4life':
            # Login successful, redirect to admin dashboard
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password.')
            return render_template('admin_login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.')
    return redirect(url_for('index'))

@app.route('/about_us')
def about_us():
    try:
        return render_template('about_us.html')
    except Exception as e:
        traceback.print_exc()
        return str(e), 500

@app.route('/home')
def home():
    return redirect(url_for('index')) 

@app.route('/static/uploads/<path:filename>')
def serve_file(filename):
    response = send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

if __name__ == '__main__':
    print(app.config['UPLOAD_FOLDER'])
    app.run()
