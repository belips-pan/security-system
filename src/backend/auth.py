from functools import wraps
from flask import request, jsonify, current_app
import jwt
from models import User, UserSession, AuditLog, db, Agent, hash_api_key  # FIXED: Added Agent import
from datetime import datetime

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(' ')[1]
            except IndexError:
                return jsonify({'message': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            
            if not current_user or not current_user.is_active:
                return jsonify({'message': 'User not found or inactive'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({'message': 'API key is missing'}), 401
        
        # Check agent API key - FIXED: consistent with app.py (lookup by hash)
        agent = Agent.query.filter_by(api_key=hash_api_key(api_key)).first()
        if agent:
            # Update last_seen
            agent.last_seen = datetime.utcnow()
            db.session.commit()
            return f(agent, *args, **kwargs)
        
        # Check user API key (lookup by hash)
        user = User.query.filter_by(api_key=hash_api_key(api_key)).first()
        if user and user.is_active:
            return f(user, *args, **kwargs)
        
        return jsonify({'message': 'Invalid API key'}), 401
    
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.role != 'admin':
            return jsonify({'message': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

def log_audit(user_id, action, resource=None, details=None):
    """Log audit trail"""
    try:
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            resource=resource,
            ip_address=request.remote_addr if request else None,
            user_agent=request.headers.get('User-Agent') if request else None,
            details=details
        )
        db.session.add(audit_log)
        db.session.commit()
    except Exception as e:
        current_app.logger.error(f"Audit log failed: {e}")
