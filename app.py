from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import random
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import SubmitField

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'thisissecret')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hms.db'

# Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME') or 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD') or 'your_email_password'

db = SQLAlchemy(app)
mail = Mail(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ----------------------- Models -----------------------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), nullable=False)

class Patient(db.Model):
    __tablename__ = 'patient'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(255), nullable=True)
    emergency_contact = db.Column(db.String(150), nullable=True)
    # Foreign key to link to the user table
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    # Relationship to the User model
    user = db.relationship('User', backref=db.backref('patient_profile', uselist=False))
    def __repr__(self):
        return f"<Patient {self.full_name}>"


class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'))
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date = db.Column(db.DateTime, nullable=False)
    reason = db.Column(db.String(255))
    status = db.Column(db.String(50), default='Pending')
    patient = db.relationship('Patient', backref='appointments')
    doctor = db.relationship('User', backref='appointments')

class Billing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    method = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
class Vitals(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'))
    temperature = db.Column(db.String(10))
    blood_pressure = db.Column(db.String(20))
    pulse = db.Column(db.String(10))
    nurse_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    patient = db.relationship('Patient', backref='vitals')
    nurse = db.relationship('User', backref='vitals_taken')


class NursingNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'))
    nurse_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    patient = db.relationship('Patient', backref='nursing_notes')
    nurse = db.relationship('User', backref='nursing_notes_written')

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nurse_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    description = db.Column(db.Text)
    completed = db.Column(db.Boolean, default=False)
    nurse = db.relationship('User', backref='tasks')


class Medication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'))
    name = db.Column(db.String(100))
    dosage = db.Column(db.String(100))
    administered = db.Column(db.Boolean, default=False)
    patient = db.relationship('Patient', backref='medications')

# At the top or below other form classes
class DummyForm(FlaskForm):
    submit = SubmitField('Delete')


# ------------------ User Loader ------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------------ Role Decorator ------------------

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                flash("Unauthorized access", "danger")
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ------------------ Routes ------------------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        if User.query.filter_by(email=email).first():
            flash('Email already exists. Please log in or reset your password.', 'warning')
            return redirect(url_for('login'))

        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            role=role
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect_to_dashboard(user.role)
        else:
            flash('Invalid credentials.', 'danger')

    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            code = str(random.randint(100000, 999999))
            session['reset_email'] = email
            session['reset_code'] = code

            msg = Message('Password Reset Code', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f'Your password reset code is: {code}'
            mail.send(msg)

            flash('Reset code sent to your email.', 'info')
            return redirect(url_for('verify_reset_code'))
        else:
            flash('No user found with that email.', 'danger')

    return render_template('forgot_password.html')

@app.route('/verify-reset', methods=['GET', 'POST'])
def verify_reset_code():
    if request.method == 'POST':
        entered_code = request.form['code']
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        if session.get('reset_code') != entered_code:
            flash('Invalid reset code.', 'danger')
            return redirect(url_for('verify_reset_code'))

        if new_password != confirm_password:
            flash('Passwords do not match.', 'warning')
            return redirect(url_for('verify_reset_code'))

        user = User.query.filter_by(email=session.get('reset_email')).first()
        if user:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            session.pop('reset_email', None)
            session.pop('reset_code', None)
            flash('Password reset successful. You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('index'))

# ---------------- Dashboard Routing Logic ----------------

def redirect_to_dashboard(role):
    route_map = {
        'admin': 'admin_dashboard',
        'doctor': 'doctor_dashboard',
        'nurse': 'nurse_dashboard',
        'receptionist': 'receptionist_dashboard',
        'patient': 'patient_dashboard'
    }
    return redirect(url_for(route_map.get(role, 'index')))

# ---------------- Receptionist Routes ----------------

@app.route('/receptionist/dashboard')
@role_required('receptionist')
def receptionist_dashboard():
    today = datetime.today().date()
    todays_appointments = Appointment.query.filter(Appointment.date >= today).count()
    new_patients = Patient.query.order_by(Patient.id.desc()).limit(5).all()
    return render_template('receptionist/dashboard.html', user=current_user, appointments=todays_appointments, patients=new_patients)

@app.route('/receptionist/register_patient')
@login_required
def register_patient():
    return render_template('receptionist/register_patient.html')

@app.route('/receptionist/appointments')
@login_required
def view_appointments():
    return render_template('receptionist/appointments.html')

@app.route('/receptionist/check_in', methods=['GET', 'POST'])
@login_required
def check_in_patient():
    if request.method == 'POST':
        # Example: retrieve patient ID and mark as checked in
        patient_id = request.form.get('patient_id')
        patient = Patient.query.get(patient_id)
        if patient:
            patient.checked_in = True  # make sure this field exists
            db.session.commit()
            flash('Patient checked in successfully!', 'success')
        return redirect(url_for('view_patients'))  # or wherever you want

    patients = Patient.query.all()
    return render_template('receptionist/check_in.html', patients=patients)

@app.route('/receptionist/billing')
@login_required
@role_required('receptionist')
def billing():
    # You can pass billing data to the template here
    return render_template('receptionist/billing.html')

# ---------------- Admin Routes (Complete Set Based on UI) ----------------

@app.route('/admin/dashboard')
@role_required('admin')
def admin_dashboard():
    total_users = User.query.count()
    total_doctors = User.query.filter_by(role='doctor').count()
    total_nurses = User.query.filter_by(role='nurse').count()
    total_patients = Patient.query.count()
    appointments_today = Appointment.query.filter(Appointment.date == datetime.today().date()).count()

    return render_template(
        'admindashboard/admin.html',
        user=current_user,
        total_users=total_users,
        total_doctors=total_doctors,
        total_nurses=total_nurses,
        total_patients=total_patients,
        appointments_today=appointments_today
    )

# Manage All Users
@app.route('/admin/users')
@role_required('admin')
def manage_users():
    users = User.query.all()
    form = DummyForm()
    return render_template('admindashboard/manage_users.html', users=users, form=form)


# Register New User
@app.route('/admin/users/register', methods=['GET', 'POST'])
@role_required('admin')
def register_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        role = request.form['role']
        password = generate_password_hash(request.form['password'])

        new_user = User(username=username, email=email, role=role, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('New user registered successfully.')
        return redirect(url_for('manage_users'))

    return render_template('admindashboard/register_user.html')

# Edit User
@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@role_required('admin')
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.name = request.form.get('username')
        user.email = request.form.get('email')
        user.role = request.form.get('role')
        
        # Optional: Update password if provided
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password:
            if new_password == confirm_password:
                user.password = generate_password_hash(new_password)
            else:
                flash('Passwords do not match.', 'danger')
                return redirect(request.url)
        
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('manage_users'))

    return render_template('admindashboard/edit_user.html', user=user)
# Delete User
@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@role_required('admin')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('manage_users'))

# View User Profile/Details
@app.route('/admin/users/view/<int:user_id>')
@role_required('admin')
def view_user(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('admindashboard/view_user.html', user=user)

# Search Users
@app.route('/admin/users/search', methods=['GET'])
@role_required('admin')
def search_users():
    query = request.args.get('query')
    users = User.query.filter(User.username.ilike(f'%{query}%')).all()
    return render_template('admindashboard/manage_users.html', users=users)

# Export User List (e.g., to CSV)
@app.route('/admin/users/export')
@role_required('admin')
def export_users():
    users = User.query.all()
    # Placeholder for exporting logic (CSV or PDF)
    return "Export functionality coming soon."

# Existing Admin Pages
@app.route('/admin/patients')
@role_required('admin')
def manage_patients():
    return render_template('admindashboard/manage_patients.html')

@app.route('/admin/doctors')
@role_required('admin')
def manage_doctors():
    return render_template('admindashboard/manage_doctors.html')

@app.route('/admin/nurses')
@role_required('admin')
def manage_nurses():
    return render_template('admindashboard/manage_nurses.html')

@app.route('/admin/appointments')
@role_required('admin')
def manage_appointments():
    return render_template('admindashboard/manage_appointments.html')

@app.route('/admin/departments')
@role_required('admin')
def manage_departments():
    return render_template('admindashboard/manage_departments.html')

@app.route('/admin/settings')
@role_required('admin')
def settings():
    return render_template('admindashboard/settings.html')

@app.route('/admin/reports')
@role_required('admin')
def view_reports():
    return render_template('admindashboard/view_reports.html')

# ---------------- Doctor Routes ----------------
@app.route('/doctor/dashboard')
@role_required('doctor')
def doctor_dashboard():
    return render_template('doctor_dashboard.html', user=current_user)

# ---------------- Nurse Routes ----------------
@app.route('/nurse/dashboard')
@role_required('nurse')
def nurse_dashboard():
    return render_template('nursedashboard/dashboard.html', user=current_user)

@app.route('/nurse/patients')
@role_required('nurse')
def view_patients():
    mock_patients = [
        {'id': 1, 'name': 'John Doe', 'age': 35, 'gender': 'Male'},
        {'id': 2, 'name': 'Jane Smith', 'age': 28, 'gender': 'Female'},
        {'id': 3, 'name': 'Ali Mwangi', 'age': 42, 'gender': 'Male'},
    ]
    return render_template('nursedashboard/patients.html', patients=mock_patients)

@app.route('/nurse/patients/<int:patient_id>/record-vitals', methods=['GET', 'POST'])
@role_required('nurse')
def nurse_record_vitals(patient_id):
    patient = {'id': patient_id, 'name': f"Mock Patient {patient_id}"}
    if request.method == 'POST':
        flash('Vitals recorded.', 'success')
        return redirect(url_for('view_patients'))
    return render_template('nursedashboard/record_vitals.html', patient=patient)

@app.route('/nurse/patients/<int:patient_id>/notes', methods=['GET', 'POST'])
@role_required('nurse')
def nurse_nursing_notes(patient_id):
    patient = {'id': patient_id, 'name': f"Mock Patient {patient_id}"}
    notes = []
    if request.method == 'POST':
        flash('Note added.', 'success')
    return render_template('nursedashboard/notes.html', patient=patient, notes=notes)

@app.route('/nurse/patients/<int:patient_id>/medications')
@role_required('nurse')
def nurse_view_medications(patient_id):
    patient = {'id': patient_id, 'name': f"Mock Patient {patient_id}"}
    medications = []
    return render_template('nursedashboard/medications.html', patient=patient, medications=medications)
@app.route('/nurse/tasks')
@role_required('nurse')
def daily_tasks():
    tasks = Task.query.filter_by(nurse_id=current_user.id).all()
    return render_template('nursedashboard/tasks.html', tasks=tasks)
# ---------------- Patient Routes ----------------
@app.route('/patient/dashboard')
@login_required
def patient_dashboard():
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    appointments = []
    if patient:
        appointments = Appointment.query.filter_by(patient_id=patient.id).order_by(Appointment.date.desc()).all()
    
    return render_template(
        'patientdashboard/dashboard.html',
        patient=patient,
        appointments=appointments
    )
# ---------------- Run App ----------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True, host='0.0.0.0', port=5000)
