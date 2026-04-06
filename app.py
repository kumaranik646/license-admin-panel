import os
import uuid
import json
import hashlib
import threading
import requests
import random
import time
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-secret-key-change-in-production')

# ডাটাবেস কনফিগারেশন - PostgreSQL (Render) অথবা SQLite (লোকাল)
database_url = os.environ.get('DATABASE_URL')
if database_url:
    # Render 'postgres://' দেয়, SQLAlchemy 'postgresql://' চায়
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url.replace("postgres://", "postgresql://", 1)
else:
    # লোকাল ডেভেলপমেন্টের জন্য SQLite
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "instance", "license.db")}'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ========== ডাটাবেস মডেল ==========

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255))
    role = db.Column(db.String(20), default='sub_admin')
    permissions = db.Column(db.Text)
    created_by = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    status = db.Column(db.Boolean, default=True)
    
    def get_permissions(self):
        if self.role == 'admin':
            return ['all']
        return json.loads(self.permissions) if self.permissions else []
    
    def set_permissions(self, perm_list):
        self.permissions = json.dumps(perm_list)
    
    def has_permission(self, permission):
        if self.role == 'admin':
            return True
        return permission in self.get_permissions()

class License(db.Model):
    __tablename__ = 'licenses'
    id = db.Column(db.Integer, primary_key=True)
    license_key = db.Column(db.String(100), unique=True, nullable=False)
    device_id = db.Column(db.String(100))
    status = db.Column(db.String(20), default='active')
    expiry_date = db.Column(db.DateTime, nullable=False)
    notes = db.Column(db.Text)
    created_by = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_verified = db.Column(db.DateTime)

class LicenseLog(db.Model):
    __tablename__ = 'license_logs'
    id = db.Column(db.Integer, primary_key=True)
    license_key = db.Column(db.String(100))
    device_id = db.Column(db.String(100))
    status = db.Column(db.String(50))
    ip_address = db.Column(db.String(50))
    verified_at = db.Column(db.DateTime, default=datetime.utcnow)

class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    username = db.Column(db.String(100))
    action = db.Column(db.String(255))
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ========== হেল্পার ফাংশন ==========

def hash_password(password):
    salt = os.environ.get('PASSWORD_SALT', 'default-salt')
    return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()

def verify_password(password, hashed):
    salt = os.environ.get('PASSWORD_SALT', 'default-salt')
    return hashlib.sha256(f"{password}{salt}".encode()).hexdigest() == hashed

def get_current_time():
    return datetime.now(timezone.utc).replace(tzinfo=None)

def generate_license_key():
    return f"AP-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}"

def log_activity(user_id, username, action, details=None):
    try:
        log = ActivityLog(
            user_id=user_id,
            username=username,
            action=action,
            details=details,
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
    except:
        pass

@app.context_processor
def utility_processor():
    return dict(now=get_current_time())

# ========== অথ রাউট ==========

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username, status=True).first()
        
        if user and verify_password(password, user.password):
            login_user(user)
            user.last_login = get_current_time()
            db.session.commit()
            log_activity(user.id, user.username, 'login', 'User logged in')
            flash(f'Welcome {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_activity(current_user.id, current_user.username, 'logout', 'User logged out')
    logout_user()
    flash('Logged out', 'info')
    return redirect(url_for('login'))

# ========== ড্যাশবোর্ড ==========

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        total_licenses = License.query.count()
        active_licenses = License.query.filter(
            License.status == 'active',
            License.expiry_date > get_current_time()
        ).count()
        expired_licenses = License.query.filter(License.expiry_date < get_current_time()).count()
        expiring_soon = License.query.filter(
            License.status == 'active',
            License.expiry_date > get_current_time(),
            License.expiry_date < get_current_time() + timedelta(days=7)
        ).count()
        total_users = User.query.count()
    else:
        total_licenses = License.query.filter_by(created_by=current_user.id).count()
        active_licenses = License.query.filter(
            License.created_by == current_user.id,
            License.status == 'active',
            License.expiry_date > get_current_time()
        ).count()
        expired_licenses = License.query.filter(
            License.created_by == current_user.id,
            License.expiry_date < get_current_time()
        ).count()
        expiring_soon = License.query.filter(
            License.created_by == current_user.id,
            License.status == 'active',
            License.expiry_date > get_current_time(),
            License.expiry_date < get_current_time() + timedelta(days=7)
        ).count()
        total_users = None
    
    recent_logs = LicenseLog.query.order_by(LicenseLog.verified_at.desc()).limit(10).all()
    
    return render_template('dashboard.html',
                         total_licenses=total_licenses,
                         active_licenses=active_licenses,
                         expired_licenses=expired_licenses,
                         expiring_soon=expiring_soon,
                         total_users=total_users,
                         recent_logs=recent_logs)

# ========== লাইসেন্স ম্যানেজমেন্ট ==========

@app.route('/licenses')
@login_required
def licenses():
    if current_user.role == 'admin':
        licenses_list = License.query.order_by(License.created_at.desc()).all()
    else:
        licenses_list = License.query.filter_by(created_by=current_user.id).order_by(License.created_at.desc()).all()
    return render_template('licenses.html', licenses=licenses_list)

@app.route('/license/create', methods=['GET', 'POST'])
@login_required
def create_license():
    if request.method == 'POST':
        license_key = request.form.get('license_key') or generate_license_key()
        expiry_days = int(request.form.get('expiry_days', 365))
        expiry_date = get_current_time() + timedelta(days=expiry_days)
        status = request.form.get('status', 'active')
        notes = request.form.get('notes', '')
        
        license = License(
            license_key=license_key,
            expiry_date=expiry_date,
            status=status,
            notes=notes,
            created_by=current_user.id
        )
        db.session.add(license)
        db.session.commit()
        
        log_activity(current_user.id, current_user.username, 'create_license', f'Created: {license_key}')
        flash(f'✅ License created: {license_key}', 'success')
        return redirect(url_for('licenses'))
    
    return render_template('create_license.html')

@app.route('/license/delete/<int:id>')
@login_required
def delete_license(id):
    license = License.query.get_or_404(id)
    if current_user.role != 'admin' and license.created_by != current_user.id:
        flash('Permission denied', 'danger')
        return redirect(url_for('licenses'))
    
    db.session.delete(license)
    db.session.commit()
    flash('License deleted', 'success')
    return redirect(url_for('licenses'))

@app.route('/license/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_license(id):
    license = License.query.get_or_404(id)
    if current_user.role != 'admin' and license.created_by != current_user.id:
        flash('Permission denied', 'danger')
        return redirect(url_for('licenses'))
    
    if request.method == 'POST':
        license.expiry_date = datetime.strptime(request.form.get('expiry_date'), '%Y-%m-%d')
        license.status = request.form.get('status')
        license.notes = request.form.get('notes', '')
        db.session.commit()
        flash('License updated', 'success')
        return redirect(url_for('licenses'))
    
    return render_template('edit_license.html', license=license)

# ========== এপিআই ভেরিফিকেশন (লাইসেন্স চেক) ==========

@app.route('/api/validate')
def api_validate():
    license_key = request.args.get('key')
    device_id = request.args.get('device', '')
    
    if not license_key:
        return jsonify({'status': 'error', 'message': 'License key required'})
    
    license = License.query.filter_by(license_key=license_key).first()
    
    log = LicenseLog(
        license_key=license_key,
        device_id=device_id,
        status='found' if license else 'not_found',
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    if not license:
        return jsonify({'status': 'invalid', 'message': 'License key not found'})
    
    if license.status != 'active':
        return jsonify({'status': 'inactive', 'message': f'License is {license.status}'})
    
    if license.expiry_date < get_current_time():
        return jsonify({'status': 'expired', 'message': 'License has expired'})
    
    license.last_verified = get_current_time()
    if device_id and not license.device_id:
        license.device_id = device_id
    db.session.commit()
    
    days_left = (license.expiry_date - get_current_time()).days
    
    return jsonify({
        'status': 'active',
        'message': 'License valid',
        'expiry_date': license.expiry_date.strftime('%Y-%m-%d %H:%M:%S'),
        'days_left': days_left
    })

# ========== ইউজার ম্যানেজমেন্ট (শুধু অ্যাডমিন) ==========

@app.route('/users')
@login_required
def users():
    if current_user.role != 'admin':
        flash('Admin access required', 'danger')
        return redirect(url_for('dashboard'))
    users_list = User.query.order_by(User.created_at.desc()).all()
    return render_template('users.html', users=users_list)

@app.route('/user/create', methods=['GET', 'POST'])
@login_required
def create_user():
    if current_user.role != 'admin':
        flash('Admin access required', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        role = request.form.get('role', 'sub_admin')
        permissions = request.form.getlist('permissions')
        
        if User.query.filter_by(username=username).first():
            flash('Username exists', 'danger')
            return redirect(url_for('create_user'))
        
        user = User(
            username=username,
            password=hash_password(password),
            email=email,
            role=role,
            created_by=current_user.id,
            status=True
        )
        user.set_permissions(permissions)
        db.session.add(user)
        db.session.commit()
        
        log_activity(current_user.id, current_user.username, 'create_user', f'Created: {username}')
        flash(f'User {username} created. Password: {password}', 'success')
        return redirect(url_for('users'))
    
    available_permissions = [
        'view_licenses', 'create_licenses', 'edit_licenses', 'delete_licenses',
        'view_logs', 'api_access'
    ]
    return render_template('create_user.html', permissions=available_permissions)

@app.route('/user/suspend/<int:id>')
@login_required
def suspend_user(id):
    if current_user.role != 'admin':
        flash('Admin access required', 'danger')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(id)
    if user.id != current_user.id:
        user.status = False
        db.session.commit()
        flash(f'User {user.username} suspended', 'warning')
    return redirect(url_for('users'))

@app.route('/user/activate/<int:id>')
@login_required
def activate_user(id):
    if current_user.role != 'admin':
        flash('Admin access required', 'danger')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(id)
    user.status = True
    db.session.commit()
    flash(f'User {user.username} activated', 'success')
    return redirect(url_for('users'))

@app.route('/user/delete/<int:id>')
@login_required
def delete_user(id):
    if current_user.role != 'admin':
        flash('Admin access required', 'danger')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(id)
    if user.id != current_user.id and user.role != 'admin':
        db.session.delete(user)
        db.session.commit()
        flash(f'User deleted', 'success')
    return redirect(url_for('users'))

@app.route('/user/permissions/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_user_permissions(id):
    if current_user.role != 'admin':
        flash('Admin access required', 'danger')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(id)
    
    if request.method == 'POST':
        permissions = request.form.getlist('permissions')
        user.set_permissions(permissions)
        db.session.commit()
        flash(f'Permissions updated for {user.username}', 'success')
        return redirect(url_for('users'))
    
    available_permissions = [
        'view_licenses', 'create_licenses', 'edit_licenses', 'delete_licenses',
        'view_logs', 'api_access'
    ]
    return render_template('edit_permissions.html', user=user, permissions=available_permissions)

# ========== লগস ==========

@app.route('/logs')
@login_required
def logs():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    pagination = ActivityLog.query.order_by(ActivityLog.created_at.desc()).paginate(page=page, per_page=per_page)
    return render_template('logs.html', logs=pagination)

@app.route('/api/docs')
@login_required
def api_docs():
    return render_template('api_docs.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        email = request.form.get('email')
        if email:
            current_user.email = email
        
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        
        if current_password and new_password:
            if verify_password(current_password, current_user.password):
                current_user.password = hash_password(new_password)
                flash('Password changed', 'success')
            else:
                flash('Current password incorrect', 'danger')
        
        db.session.commit()
        flash('Profile updated', 'success')
        return redirect(url_for('profile'))
    
    return render_template('profile.html')

# ========== ডাটাবেস তৈরি ও ডিফল্ট অ্যাডমিন ==========

with app.app_context():
    db.create_all()
    
    if not User.query.filter_by(role='admin').first():
        admin = User(
            username='admin',
            password=hash_password('admin123'),
            email='admin@example.com',
            role='admin',
            status=True
        )
        db.session.add(admin)
        db.session.commit()
        print("✅ Default admin created: admin / admin123")
    
    if License.query.count() == 0:
        demo = License(
            license_key='AP-DEMO-2024-001',
            expiry_date=get_current_time() + timedelta(days=365),
            status='active',
            notes='Demo license'
        )
        db.session.add(demo)
        db.session.commit()
        print("✅ Demo license created")

# ========== সেলফ পিং সিস্টেম (সার্ভার নিজেই নিজেকে জাগিয়ে রাখে) ==========

def start_self_ping():
    """প্রতি ৮-১২ মিনিট পর পর নিজেকে পিং দিয়ে সার্ভারকে জাগিয়ে রাখে"""
    
    def ping_loop():
        # Render এ থাকলে নিজের URL বের করুন
        if os.environ.get('RENDER'):
            # RENDER_EXTERNAL_HOSTNAME এ আপনার অ্যাপের URL থাকে
            hostname = os.environ.get('RENDER_EXTERNAL_HOSTNAME', '')
            if hostname:
                base_url = f"https://{hostname}"
            else:
                # যদি RENDER_EXTERNAL_HOSTNAME না থাকে, তাহলে Render দেওয়া URL ব্যবহার করুন
                base_url = "https://license-admin-panel-evb7.onrender.com"  # আপনার Render URL বসান
        else:
            # লোকাল ডেভেলপমেন্টের জন্য
            base_url = "http://localhost:5000"
        
        ping_url = f"{base_url}/api/validate?key=self_ping_keepalive&device=self"
        
        while True:
            # ৮ থেকে ১২ মিনিটের মধ্যে র্যান্ডম সময় (480-720 সেকেন্ড)
            interval = random.randint(480, 720)
            time.sleep(interval)
            
            try:
                response = requests.get(ping_url, timeout=10)
                print(f"✅ Self-ping sent at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Status: {response.status_code}")
            except Exception as e:
                print(f"❌ Self-ping failed: {e}")
    
    # ব্যাকগ্রাউন্ড ডেমন থ্রেড শুরু করুন
    ping_thread = threading.Thread(target=ping_loop)
    ping_thread.daemon = True
    ping_thread.start()
    print("🚀 Self-ping system started! Server will ping itself every 8-12 minutes.")

# শুধু Render এনভায়রনমেন্টে সেলফ-পিং চালু করুন (লোকালে চালানোর দরকার নেই)
if os.environ.get('RENDER'):
    start_self_ping()
else:
    print("📍 Running in local mode - self-ping disabled")

# ========== এন্ট্রি পয়েন্ট ==========

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
