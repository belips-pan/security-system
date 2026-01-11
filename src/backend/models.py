from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json
import bcrypt
import secrets

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    api_key = db.Column(db.String(64), unique=True, index=True)
    
    def set_password(self, password):
        """Hash and set password"""
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def check_password(self, password):
        """Verify password"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def generate_api_key(self):
        """Generate API key for the user"""
        self.api_key = secrets.token_urlsafe(32)
        return self.api_key
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active
        }
    
    @classmethod
    def authenticate(cls, username, password):
        """Authenticate user with username and password"""
        user = cls.query.filter_by(username=username).first()
        if user and user.check_password(password) and user.is_active:
            user.last_login = datetime.utcnow()
            db.session.commit()
            return user
        return None
    
    @classmethod
    def get_by_api_key(cls, api_key):
        """Get user by API key"""
        return cls.query.filter_by(api_key=api_key, is_active=True).first()

class Agent(db.Model):
    __tablename__ = 'agents'
    
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    agent_type = db.Column(db.String(50), nullable=False, index=True)
    location = db.Column(db.String(100))
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    api_key = db.Column(db.String(64), unique=True, index=True)
    
    telemetry_data = db.relationship('Telemetry', backref='agent', lazy=True, cascade='all, delete-orphan')
    alerts = db.relationship('Alert', backref='agent', lazy=True, cascade='all, delete-orphan')
    
    @classmethod
    def get_by_api_key(cls, api_key):
        """Get agent by API key"""
        return cls.query.filter_by(api_key=api_key).first()

class Telemetry(db.Model):
    __tablename__ = 'telemetry'
    
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id', ondelete='CASCADE'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    security_score = db.Column(db.Integer)
    metrics = db.Column(db.Text)
    anomalies = db.Column(db.Text)
    
    def get_metrics(self):
        return json.loads(self.metrics) if self.metrics else {}
    
    def get_anomalies(self):
        return json.loads(self.anomalies) if self.anomalies else []

class Alert(db.Model):
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id', ondelete='CASCADE'), nullable=False, index=True)  # FIXED: ForeignKey to agents.id
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    severity = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=False)
    resolved = db.Column(db.Boolean, default=False)
    resolved_at = db.Column(db.DateTime)
    
    def to_dict(self):
        return {
            'id': self.id,
            'agent_id': self.agent.agent_id if self.agent else None,  # FIXED: return agent_id string
            'timestamp': self.timestamp.isoformat(),
            'severity': self.severity,
            'message': self.message,
            'resolved': self.resolved
        }

# Additional models for completeness
class UserSession(db.Model):
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    token = db.Column(db.String(500), nullable=False, index=True)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
    action = db.Column(db.String(100), nullable=False, index=True)
    resource = db.Column(db.String(100))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    details = db.Column(db.Text)