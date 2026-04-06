from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import json

db = SQLAlchemy()

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
    device_id = db.Column(db.String(100), nullable=True)
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