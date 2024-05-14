from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_bcrypt import Bcrypt
import os
import traceback
import secrets

# Generate secret key
secret_key = secrets.token_hex(16)

app = Flask(__name__, static_folder='static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///real_estate.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.secret_key = secret_key
app.debug = True  # Enable debug mode
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)

# Define database models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(100), nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Apartment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    media = db.relationship('Media', backref='apartment', lazy=True)

class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

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
    admin = Admin.query.filter_by(username='Thomax').first()
    if not admin:
        admin = Admin(username='Thomax', password='blues4life')
        db.session.add(admin)
        db.session.commit()

# Define routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return 'Welcome, {}'.format(current_user.username)
    return render_template('index.html')

@app.route('/real_estate')
def real_estate():
    try:
        locations = Location.query.all()
        return render_template('real_estate.html', locations=locations)
    except Exception as e:
        traceback.print_exc()
        return str(e), 500

@app.route('/rent')
def rent():
    app.logger.debug("Rendering rent.html")
    return render_template('rent.html')

@app.route('/shomolu.html')
def shomolu():
    return render_template('shomolu.html')

@app.route('/surulere.html')
def surulere():
    return render_template('surulere.html')

@app.route('/pedro.html')
def pedro():
    return render_template('pedro.html')

@app.route('/ladilak.html')
def ladilak():
    return render_template('ladilak.html')

@app.route('/palmgrove.html')
def palmgrove():
    return render_template('palmgrove.html')

@app.route('/bariga.html')
def bariga():
    return render_template('bariga.html')

@app.route('/gbagada.html')
def gbagada():
    return render_template('gbagada.html')

@app.route('/yaba.html')
def yaba():
    return render_template('yaba.html')

@app.route('/sabo.html')
def sabo():
    return render_template('sabo.html')

@app.route('/rent.html')
def rent_page():
    return render_template('rent.html')

@app.route('/real_estate_home')
def real_estate_home():
    return render_template('real_estate.html')

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
        apartment_id = request.form.get('apartment_id')
        if file and apartment_id:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
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
        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password.')
    return render_template('admin_login.html')

@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            media = Media(filename=filename)
            db.session.add(media)
            db.session.commit()
            flash('File uploaded successfully!')
        else:
            flash('No file selected!')

    medias = Media.query.all()
    return render_template('admin_dashboard.html', medias=medias)

@app.route('/register_now', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if request.form['password'] != request.form['confirm_password']:
            error = "Passwords do not match"
            return render_template('register.html', error=error)
        
        username = request.form['username']
        password = request.form['password']
        role = 'user'
        
        if User.query.filter_by(username=username).first():
            error = "Username already exists"
            return render_template('register.html', error=error)
        
        new_user = User(username=username, role=role)
        new_user.set_password(password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful. Please login.')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            error = "An error occurred while registering. Please try again."
            print(e)
            return render_template('register.html', error=error)

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.')
    return redirect(url_for('index'))

@app.route('/about_us')
def about_us():
    return render_template('about_us.html')

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
    print("Database URI:", app.config['SQLALCHEMY_DATABASE_URI'])
    app.run()
