from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from datetime import datetime, timedelta, timezone
from functools import wraps
import hashlib
import uuid
import os
import json
import requests
from dotenv import load_dotenv
from sqlalchemy import text

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-key')

# PostgreSQL ডাটাবেস কনফিগারেশন (Railway এর জন্য)
database_url = os.environ.get('DATABASE_URL')
if database_url:
    # Railway 'postgres://' দেয়, SQLAlchemy 'postgresql://' চায়
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url.replace("postgres://", "postgresql://", 1)
else:
    # লোকাল ডেভেলপমেন্টের জন্য SQLite
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "instance", "license.db")}'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 3600,
}

from database import db, User, License, LicenseLog, ActivityLog
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ========== TEMPLATE CONTEXT PROCESSOR ==========
@app.context_processor
def utility_processor():
    def get_now():
        return datetime.now(timezone.utc).replace(tzinfo=None)
    return dict(now=get_now())

# ========== HELPER FUNCTIONS ==========

def hash_password(password):
    salt = os.getenv('PASSWORD_SALT', 'default-salt')
    return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()

def verify_password(password, hashed):
    salt = os.getenv('PASSWORD_SALT', 'default-salt')
    return hashlib.sha256(f"{password}{salt}".encode()).hexdigest() == hashed

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

def generate_license_key():
    return f"AP-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}"

def get_current_time():
    return datetime.now(timezone.utc).replace(tzinfo=None)

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please login', 'warning')
                return redirect(url_for('login'))
            if not current_user.has_permission(permission):
                flash(f'You need {permission} permission', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated
    return decorator

# ========== LICENSE QUERY HELPER ==========

def get_visible_licenses():
    if current_user.role == 'admin':
        return License.query.order_by(License.created_at.desc())
    else:
        return License.query.filter_by(created_by=current_user.id).order_by(License.created_at.desc())

def can_edit_license(license):
    if current_user.role == 'admin':
        return True
    return current_user.has_permission('edit_licenses') and license.created_by == current_user.id

def can_delete_license(license):
    if current_user.role == 'admin':
        return True
    return current_user.has_permission('delete_licenses') and license.created_by == current_user.id

# ========== AUTH ROUTES ==========

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
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))

# ========== DASHBOARD ==========

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

# ========== LICENSE MANAGEMENT ==========

@app.route('/licenses')
@login_required
@permission_required('view_licenses')
def licenses():
    licenses_list = get_visible_licenses().all()
    return render_template('licenses.html', licenses=licenses_list)

@app.route('/license/create', methods=['GET', 'POST'])
@login_required
@permission_required('create_licenses')
def create_license():
    if request.method == 'POST':
        try:
            license_key = request.form.get('license_key') or generate_license_key()
            device_id = request.form.get('device_id', '').strip()
            if device_id == '':
                device_id = None
            
            expiry_type = request.form.get('expiry_type', 'days')
            
            # Expiry date calculation based on type
            if expiry_type == 'custom':
                expiry_datetime_str = request.form.get('expiry_datetime_custom')
                if not expiry_datetime_str:
                    flash('Please select expiry date and time', 'danger')
                    return redirect(url_for('create_license'))
                expiry_date = datetime.strptime(expiry_datetime_str, '%Y-%m-%dT%H:%M')
            else:
                expiry_value = int(request.form.get('expiry_value', 365))
                
                if expiry_type == 'minutes':
                    expiry_date = get_current_time() + timedelta(minutes=expiry_value)
                elif expiry_type == 'hours':
                    expiry_date = get_current_time() + timedelta(hours=expiry_value)
                elif expiry_type == 'days':
                    expiry_date = get_current_time() + timedelta(days=expiry_value)
                elif expiry_type == 'months':
                    expiry_date = get_current_time() + timedelta(days=expiry_value * 30)
                elif expiry_type == 'years':
                    expiry_date = get_current_time() + timedelta(days=expiry_value * 365)
                else:
                    expiry_date = get_current_time() + timedelta(days=365)
            
            status = request.form.get('status', 'active')
            notes = request.form.get('notes', '')
            
            # Check if device ID already used
            if device_id:
                existing = License.query.filter_by(device_id=device_id).first()
                if existing:
                    flash(f'⚠️ Device ID {device_id} is already assigned to license: {existing.license_key}', 'warning')
            
            license = License(
                license_key=license_key,
                device_id=device_id,
                expiry_date=expiry_date,
                status=status,
                notes=notes,
                created_by=current_user.id
            )
            db.session.add(license)
            db.session.commit()
            
            log_activity(current_user.id, current_user.username, 'create_license', f'Created: {license_key}')
            
            # Format expiry message
            if expiry_type == 'custom':
                expiry_msg = expiry_date.strftime('%Y-%m-%d %H:%M:%S')
            else:
                expiry_msg = expiry_date.strftime('%Y-%m-%d')
            
            flash(f'✅ License created: {license_key}<br>📅 Expires: {expiry_msg}<br>🖥️ Device: {device_id or "Not assigned"}', 'success')
            return redirect(url_for('licenses'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating license: {str(e)}', 'danger')
            return redirect(url_for('create_license'))
    
    return render_template('create_license.html')

@app.route('/license/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@permission_required('edit_licenses')
def edit_license(id):
    license = License.query.get_or_404(id)
    
    if not can_edit_license(license):
        flash('You do not have permission to edit this license', 'danger')
        return redirect(url_for('licenses'))
    
    if request.method == 'POST':
        try:
            # Update device ID
            device_id = request.form.get('device_id', '').strip()
            if device_id == '':
                device_id = None
            
            if device_id:
                existing = License.query.filter(License.device_id == device_id, License.id != id).first()
                if existing:
                    flash(f'⚠️ Device ID {device_id} is already assigned to license: {existing.license_key}', 'warning')
                else:
                    license.device_id = device_id
            else:
                license.device_id = None
            
            # Update expiry date
            if request.form.get('expiry_date'):
                license.expiry_date = datetime.strptime(request.form.get('expiry_date'), '%Y-%m-%d')
            
            # Update status
            if request.form.get('status'):
                license.status = request.form.get('status')
            
            # Update notes
            license.notes = request.form.get('notes', '')
            
            db.session.commit()
            log_activity(current_user.id, current_user.username, 'edit_license', f'Edited license ID: {id}')
            flash('✅ License updated successfully', 'success')
            return redirect(url_for('licenses'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating license: {str(e)}', 'danger')
            return redirect(url_for('edit_license', id=id))
    
    return render_template('edit_license.html', license=license)

@app.route('/license/renew/<int:id>', methods=['POST'])
@login_required
@permission_required('edit_licenses')
def renew_license(id):
    license = License.query.get_or_404(id)
    
    if not can_edit_license(license):
        flash('You do not have permission to renew this license', 'danger')
        return redirect(url_for('licenses'))
    
    renew_days = int(request.form.get('renew_days', 30))
    license.expiry_date = license.expiry_date + timedelta(days=renew_days)
    license.status = 'active'
    db.session.commit()
    
    log_activity(current_user.id, current_user.username, 'renew_license', f'Renewed license {license.license_key} by {renew_days} days')
    flash(f'✅ License renewed! New expiry: {license.expiry_date.strftime("%Y-%m-%d")}', 'success')
    return redirect(url_for('licenses'))

@app.route('/license/delete/<int:id>')
@login_required
@permission_required('delete_licenses')
def delete_license(id):
    license = License.query.get_or_404(id)
    
    if not can_delete_license(license):
        flash('You do not have permission to delete this license', 'danger')
        return redirect(url_for('licenses'))
    
    db.session.delete(license)
    db.session.commit()
    log_activity(current_user.id, current_user.username, 'delete_license', f'Deleted license ID: {id}')
    flash('License deleted', 'success')
    return redirect(url_for('licenses'))

@app.route('/license/device/unassign/<int:id>')
@login_required
@permission_required('edit_licenses')
def unassign_device(id):
    license = License.query.get_or_404(id)
    license.device_id = None
    db.session.commit()
    flash(f'Device unassigned from license: {license.license_key}', 'success')
    return redirect(url_for('licenses'))

# ========== USER MANAGEMENT ==========

@app.route('/users')
@login_required
@admin_required
def users():
    users_list = User.query.order_by(User.created_at.desc()).all()
    return render_template('users.html', users=users_list)

@app.route('/user/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
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
        log_activity(current_user.id, current_user.username, 'create_user', f'Created user: {username}')
        flash(f'✅ User {username} created. Password: {password}', 'success')
        return redirect(url_for('users'))
    
    available_permissions = [
        'view_licenses', 'create_licenses', 'edit_licenses', 'delete_licenses',
        'view_logs', 'api_access'
    ]
    return render_template('create_user.html', permissions=available_permissions)

@app.route('/user/suspend/<int:id>')
@login_required
@admin_required
def suspend_user(id):
    user = User.query.get_or_404(id)
    if user.id != current_user.id:
        user.status = False
        db.session.commit()
        log_activity(current_user.id, current_user.username, 'suspend_user', f'Suspended: {user.username}')
        flash(f'⚠️ User {user.username} suspended', 'warning')
    return redirect(url_for('users'))

@app.route('/user/activate/<int:id>')
@login_required
@admin_required
def activate_user(id):
    user = User.query.get_or_404(id)
    user.status = True
    db.session.commit()
    log_activity(current_user.id, current_user.username, 'activate_user', f'Activated: {user.username}')
    flash(f'✅ User {user.username} activated', 'success')
    return redirect(url_for('users'))

@app.route('/user/delete/<int:id>')
@login_required
@admin_required
def delete_user(id):
    user = User.query.get_or_404(id)
    if user.id != current_user.id and user.role != 'admin':
        username = user.username
        db.session.delete(user)
        db.session.commit()
        log_activity(current_user.id, current_user.username, 'delete_user', f'Deleted: {username}')
        flash(f'User {username} deleted', 'success')
    return redirect(url_for('users'))

@app.route('/user/permissions/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user_permissions(id):
    user = User.query.get_or_404(id)
    
    if request.method == 'POST':
        permissions = request.form.getlist('permissions')
        user.set_permissions(permissions)
        db.session.commit()
        log_activity(current_user.id, current_user.username, 'edit_permissions', f'Edited permissions for: {user.username}')
        flash(f'✅ Permissions updated for {user.username}', 'success')
        return redirect(url_for('users'))
    
    available_permissions = [
        'view_licenses', 'create_licenses', 'edit_licenses', 'delete_licenses',
        'view_logs', 'api_access'
    ]
    return render_template('edit_permissions.html', user=user, permissions=available_permissions)

# ========== LOGS ==========

@app.route('/logs')
@login_required
@permission_required('view_logs')
def logs():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    pagination = ActivityLog.query.order_by(ActivityLog.created_at.desc()).paginate(page=page, per_page=per_page)
    return render_template('logs.html', logs=pagination)

# ========== API ==========

@app.route('/api/validate')
def api_validate():
    license_key = request.args.get('key')
    device_id = request.args.get('device', '')
    
    if not license_key:
        return jsonify({'status': 'error', 'message': 'License key required'})
    
    license = License.query.filter_by(license_key=license_key).first()
    
    # Log the attempt
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
    
    # Device lock check
    if license.device_id and license.device_id != device_id:
        return jsonify({
            'status': 'device_mismatch', 
            'message': f'This license is locked to device: {license.device_id[:10]}...'
        })
    
    # First time device assignment
    if not license.device_id and device_id:
        license.device_id = device_id
        db.session.commit()
    
    license.last_verified = get_current_time()
    db.session.commit()
    
    days_left = (license.expiry_date - get_current_time()).days
    
    return jsonify({
        'status': 'active',
        'message': 'License valid',
        'expiry_date': license.expiry_date.strftime('%Y-%m-%d %H:%M:%S'),
        'days_left': days_left
    })

@app.route('/api/docs')
@login_required
@permission_required('api_access')
def api_docs():
    return render_template('api_docs.html')

# ========== PROFILE ==========

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

# ========== INITIALIZE DATABASE ==========

with app.app_context():
    db.session.rollback()
    db.create_all()
    print("✅ Database tables created")
    
    try:
        db.session.execute(text('ALTER TABLE licenses ADD COLUMN IF NOT EXISTS device_id VARCHAR(100)'))
        db.session.commit()
        print("✅ device_id column checked/added")
    except Exception as e:
        db.session.rollback()
        print(f"Note: device_id column may already exist: {e}")
    
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
        demo_license = License(
            license_key='AP-B5D8-E8C2-9128',
            expiry_date=get_current_time() + timedelta(days=365),
            status='active',
            notes='Demo license - valid for 1 year',
            created_by=1
        )
        db.session.add(demo_license)
        db.session.commit()
        print("✅ Demo license created")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
