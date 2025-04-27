import os
import json
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = ''
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jobs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

ADZUNA_APP_ID = ''  
ADZUNA_APP_KEY = ''  
ADZUNA_BASE_URL = 'https://api.adzuna.com/v1/api/jobs'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  
    company = db.Column(db.String(100), nullable=True)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    salary = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    company = db.Column(db.String(100), nullable=False)
    posted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_external = db.Column(db.Boolean, default=False)
    external_id = db.Column(db.String(100), nullable=True)
    external_url = db.Column(db.String(200), nullable=True)
    posted_date = db.Column(db.DateTime, server_default=db.func.now())
    
    def __repr__(self):
        return f'<Job {self.title}>'

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), default='Applied')
    applied_date = db.Column(db.DateTime, server_default=db.func.now())
    cover_letter = db.Column(db.Text, nullable=True)
    
    job = db.relationship('Job', backref='applications')
    user = db.relationship('User', backref='applications')
    
    def __repr__(self):
        return f'<Application {self.id}>'

with app.app_context():
    db.create_all()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if user.role != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def employer_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if user.role != 'employer':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def job_seeker_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if user.role != 'job_seeker':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def load_sample_jobs():
    """Load sample jobs from JSON file into database"""
    try:
        with open('data/data.json', 'r') as f:
            sample_jobs = json.load(f)
        
        admin_user = User.query.filter_by(role='admin').first()
        if not admin_user:
            admin_user = User(
                username='admin',
                email='admin@example.com',
                password=generate_password_hash('admin123'),
                role='admin',
                company='Admin Company'
            )
            db.session.add(admin_user)
            db.session.commit()
        
        for job_data in sample_jobs:
            job = Job(
                title=job_data['title'],
                description=job_data['description'],
                salary=job_data['salary'],
                location=job_data['location'],
                category=job_data['category'],
                company=job_data['company'],
                posted_by=admin_user.id,
                is_external=False
            )
            db.session.add(job)
        db.session.commit()
        return True
    except Exception as e:
        print(f"Error loading sample jobs: {e}")
        return False

def fetch_external_jobs(keywords='', location='', page=1):
    """Fetch jobs from Adzuna API"""
    params = {
        'app_id': ADZUNA_APP_ID,
        'app_key': ADZUNA_APP_KEY,
        'results_per_page': 20,
    }
    try:
        if not location:
            location = 'us'  
        
        response = requests.get(f"{ADZUNA_BASE_URL}/gb/search/1", params=params)
        response.raise_for_status()  
        data = response.json()
        return data.get('results', [])
    except requests.RequestException as e:
        print(f"Error fetching external jobs: {e}")
        return []


@app.route('/withdraw-application/<int:app_id>', methods=['POST'])
@login_required
@job_seeker_required
def withdraw_application(app_id):
    application = Application.query.get_or_404(app_id)
    
    if application.user_id != session['user_id']:
        flash('You are not authorized to withdraw this application.', 'danger')
        return redirect(url_for('my_applications'))
    
    db.session.delete(application)
    db.session.commit()
    
    flash('Your application has been withdrawn successfully.', 'success')
    return redirect(url_for('my_applications'))


@app.route('/')
def index():
    internal_jobs = Job.query.filter_by(is_external=False).order_by(Job.posted_date.desc()).limit(10).all()
    return render_template('index.html', jobs=internal_jobs)

@app.route('/external-jobs')
def external_jobs():
    keywords = request.args.get('keywords', '')
    location = request.args.get('location', '')
    page = request.args.get('page', 1, type=int)
    
    external_jobs = fetch_external_jobs(keywords, location, page)
    return render_template('external_jobs.html', jobs=external_jobs, keywords=keywords, location=location, page=page)

@app.route('/job/<int:job_id>')
def job_details(job_id):
    job = Job.query.get_or_404(job_id)
    has_applied = False
    if 'user_id' in session and session['role'] == 'job_seeker':
        has_applied = Application.query.filter_by(job_id=job_id, user_id=session['user_id']).first() is not None
    return render_template('job_seeker/job_details.html', job=job, has_applied=has_applied)

@app.route('/apply/<int:job_id>', methods=['GET', 'POST'])
@login_required
@job_seeker_required
def apply_job(job_id):
    job = Job.query.get_or_404(job_id)
    if request.method == 'POST':
        cover_letter = request.form.get('cover_letter', '')
        existing_application = Application.query.filter_by(job_id=job_id, user_id=session['user_id']).first()
        if existing_application:
            flash('You have already applied for this job.', 'warning')
            return redirect(url_for('job_details', job_id=job_id))
        
        application = Application(
            job_id=job_id,
            user_id=session['user_id'],
            cover_letter=cover_letter,
            status='Applied'
        )
        db.session.add(application)
        db.session.commit()
        flash('Application submitted successfully!', 'success')
        return redirect(url_for('job_details', job_id=job_id))
    
    return render_template('job_seeker/apply_job.html', job=job)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        company = request.form.get('company', '')
        if User.query.filter_by(username=username).first():
            flash('Username already taken. Please choose another.', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please use another email.', 'danger')
            return redirect(url_for('register'))

        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            role=role,
            company=company
        )
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('auth/register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash('Login successful!', 'success')
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'employer':
                return redirect(url_for('employer_dashboard'))
            else:
                return redirect(url_for('job_seeker_dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))
    
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    users_count = User.query.count()
    jobs_count = Job.query.count()
    applications_count = Application.query.count()
    return render_template('admin/dashboard.html', 
                         users_count=users_count, 
                         jobs_count=jobs_count, 
                         applications_count=applications_count)

@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/jobs')
@admin_required
def admin_jobs():
    jobs = Job.query.all()
    return render_template('admin/jobs.html', jobs=jobs)

@app.route('/employer/dashboard')
@employer_required
def employer_dashboard():
    jobs = Job.query.filter_by(posted_by=session['user_id']).all()
    applications = []
    for job in jobs:
        applications.extend(job.applications)
    return render_template('employer/dashboard.html', jobs=jobs, applications=applications)

@app.route('/employer/post-job', methods=['GET', 'POST'])
@employer_required
def post_job():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        salary = request.form['salary']
        location = request.form['location']
        category = request.form['category']
        
        user = User.query.get(session['user_id'])
        
        job = Job(
            title=title,
            description=description,
            salary=salary,
            location=location,
            category=category,
            company=user.company,
            posted_by=user.id,
            is_external=False
        )
        db.session.add(job)
        db.session.commit()
        flash('Job posted successfully!', 'success')
        return redirect(url_for('employer_dashboard'))
    
    return render_template('employer/post_job.html')

@app.route('/employer/applications/<int:job_id>')
@employer_required
def view_applications(job_id):
    job = Job.query.get_or_404(job_id)
    if job.posted_by != session['user_id']:
        flash('You are not authorized to view these applications.', 'danger')
        return redirect(url_for('employer_dashboard'))
    
    applications = job.applications
    return render_template('employer/view_applications.html', job=job, applications=applications)

@app.route('/employer/update-application/<int:app_id>', methods=['POST'])
@employer_required
def update_application(app_id):
    application = Application.query.get_or_404(app_id)
    job = Job.query.get(application.job_id)
    
    if job.posted_by != session['user_id']:
        flash('You are not authorized to update this application.', 'danger')
        return redirect(url_for('employer_dashboard'))
    
    new_status = request.form['status']
    application.status = new_status
    db.session.commit()
    flash('Application status updated!', 'success')
    return redirect(url_for('view_applications', job_id=job.id))

@app.route('/job-seeker/dashboard')
@job_seeker_required
def job_seeker_dashboard():
    recommended_jobs = Job.query.filter_by(is_external=False).order_by(Job.posted_date.desc()).limit(5).all()
    applications = Application.query.filter_by(user_id=session['user_id']).all()
    return render_template('job_seeker/dashboard.html', 
                         recommended_jobs=recommended_jobs, 
                         applications=applications)

@app.route('/job-seeker/my-applications')
@job_seeker_required
def my_applications():
    applications = Application.query.filter_by(user_id=session['user_id']).all()
    return render_template('job_seeker/my_applications.html', applications=applications)

@app.route('/search')
def search_jobs():
    query = request.args.get('q', '')
    location = request.args.get('location', '')
    category = request.args.get('category', '')
    
    jobs_query = Job.query.filter_by(is_external=False)
    
    if query:
        jobs_query = jobs_query.filter(Job.title.ilike(f'%{query}%') | Job.description.ilike(f'%{query}%'))
    if location:
        jobs_query = jobs_query.filter(Job.location.ilike(f'%{location}%'))
    if category:
        jobs_query = jobs_query.filter(Job.category.ilike(f'%{category}%'))
    
    jobs = jobs_query.order_by(Job.posted_date.desc()).all()
    return render_template('index.html', jobs=jobs, search_query=query, location=location, category=category)

@app.before_first_request
def initialize_data():
    if Job.query.count() == 0:
        load_sample_jobs()

if __name__ == '__main__':
    app.run(debug=True)
