# Security-System/src/backend/app.py
import time
import secrets
import psycopg2
from flask import Flask, jsonify, request, session
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from flask_cors import CORS
from models import db, Agent, Telemetry, Alert, User, hash_api_key
from datetime import datetime
import json
import os
import sys

# Βεβαιώσου ότι ο φάκελος src/backend είναι στο path για τα imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from security_validation import validate_target, validate_nmap_options, validate_nuclei_template
from auth import log_audit

app = Flask(__name__)

# No insecure fallback - the app refuses to start with a guessable secret key.
try:
    app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
except KeyError:
    raise RuntimeError(
        "SECRET_KEY environment variable must be set (no insecure default is "
        "provided). See docker/.env.example."
    )

app.config['SESSION_TYPE'] = 'filesystem'

# ==================== CORS CONFIG ====================
CORS(app,
     supports_credentials=True,
     resources={
         r"/api/*": {
             "origins": ["http://192.168.56.30:3000", "http://localhost:3000"],
             "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
             "allow_headers": ["Content-Type", "X-API-Key", "Authorization", "Accept", "X-CSRF-Token"],
             "expose_headers": ["Content-Type"],
             "supports_credentials": True,
             "max_age": 3600
         }
     })

# Database configuration - FIXED for unified schema
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://admin:password@localhost:5432/security_db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Celery configuration - IMPORT THE MODULE
try:
    from celery_tasks import app as celery_app
    from celery_tasks import nmap_scan_task, nuclei_scan_task, comprehensive_scan_task, test_celery_worker
    from celery_tasks import flower_ping  # Προσθέτουμε και το flower_ping task
    CELERY_AVAILABLE = True
    print("✅ Celery module imported successfully")
except ImportError as e:
    print(f"⚠️ Celery module not available: {e}")
    CELERY_AVAILABLE = False
    celery_app = None

# Flower monitoring configuration. "localhost" would mean this container, not
# the flower container - default to the internal service DNS name/port
# instead, so it resolves within the Docker network without needing
# FLOWER_URL set explicitly. FLOWER_URL below is still respected if provided
# (e.g. to point at a Flower instance reachable via a different host).
FLOWER_URL = os.getenv('FLOWER_URL', 'http://flower:5555')
FLOWER_USERNAME = os.getenv('FLOWER_USERNAME', 'admin')
FLOWER_PASSWORD = os.getenv('FLOWER_PASSWORD', 'password')

# ==================== LOGIN RATE LIMITING ====================
# Redis-backed failed-login counter (shared correctly across the 2 gunicorn
# worker processes), with an in-memory fallback if Redis can't be reached so
# login still works (just without cross-process lockout accuracy) rather
# than hard-failing.
REDIS_URL_FOR_RATELIMIT = os.getenv('REDIS_URL', 'redis://redis:6379/0')
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 900  # 15 minutes

try:
    import redis as redis_lib
    _ratelimit_redis = redis_lib.from_url(
        REDIS_URL_FOR_RATELIMIT, socket_connect_timeout=2, socket_timeout=2
    )
    _ratelimit_redis.ping()
    print("✅ Login rate-limit backend: Redis")
except Exception as e:
    print(f"⚠️ Login rate-limit Redis unavailable, using in-memory fallback: {e}")
    _ratelimit_redis = None

_login_attempts_memory = {}  # {key: (count, first_attempt_epoch)}


def _login_attempt_key(identifier):
    return f"login_attempts:{identifier}"


def is_login_locked_out(identifier):
    if _ratelimit_redis is not None:
        try:
            count = _ratelimit_redis.get(_login_attempt_key(identifier))
            return count is not None and int(count) >= LOGIN_MAX_ATTEMPTS
        except Exception:
            pass
    entry = _login_attempts_memory.get(identifier)
    if not entry:
        return False
    count, first_time = entry
    if time.time() - first_time > LOGIN_LOCKOUT_SECONDS:
        _login_attempts_memory.pop(identifier, None)
        return False
    return count >= LOGIN_MAX_ATTEMPTS


def record_failed_login(identifier):
    if _ratelimit_redis is not None:
        try:
            key = _login_attempt_key(identifier)
            pipe = _ratelimit_redis.pipeline()
            pipe.incr(key)
            pipe.expire(key, LOGIN_LOCKOUT_SECONDS)
            pipe.execute()
            return
        except Exception:
            pass
    count, first_time = _login_attempts_memory.get(identifier, (0, time.time()))
    if time.time() - first_time > LOGIN_LOCKOUT_SECONDS:
        count, first_time = 0, time.time()
    _login_attempts_memory[identifier] = (count + 1, first_time)


def clear_failed_login(identifier):
    if _ratelimit_redis is not None:
        try:
            _ratelimit_redis.delete(_login_attempt_key(identifier))
        except Exception:
            pass
    _login_attempts_memory.pop(identifier, None)


# Απλοποιημένο API Key authentication - ΜΟΝΟ από βάση δεδομένων
def require_api_key(f):
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            # Έλεγξε για session authentication (για frontend)
            if session.get('authenticated'):
                return f(*args, **kwargs)
            return jsonify({"error": "API Key is missing", "details": "Include X-API-Key header"}), 401

        # Έλεγχος Agent API key από βάση δεδομένων (lookup by hash - api_key
        # columns store hash_api_key(raw), never the raw secret)
        agent = Agent.query.filter_by(api_key=hash_api_key(api_key)).first()
        if agent:
            # Ενημέρωση last_seen για agent
            agent.last_seen = datetime.utcnow()
            db.session.commit()
            request.agent_type = agent.agent_type
            request.agent_id = agent.agent_id
            return f(*args, **kwargs)

        # Έλεγχος User API key από βάση δεδομένων
        user = User.query.filter_by(api_key=hash_api_key(api_key), is_active=True).first()
        if user:
            request.agent_type = f"user_{user.role}"
            request.user_id = user.id
            return f(*args, **kwargs)

        return jsonify({"error": "Invalid API Key", "details": "Key not found in database"}), 401

    decorated.__name__ = f.__name__
    return decorated

def require_frontend_auth(f):
    """Authentication για το frontend (χωρίς API key)"""
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)

    decorated.__name__ = f.__name__
    return decorated


def require_csrf(f):
    """CSRF protection (double-submit token) for session-authenticated,
    state-changing routes. The token is minted at login and stored in the
    session; the frontend must echo it back via the X-CSRF-Token header.
    """
    def decorated(*args, **kwargs):
        token = request.headers.get('X-CSRF-Token')
        if not token or token != session.get('csrf_token'):
            return jsonify({"error": "Invalid or missing CSRF token"}), 403
        return f(*args, **kwargs)

    decorated.__name__ = f.__name__
    return decorated


def require_scan_access(f):
    """Human User accounts (via a logged-in session or a User API key) and
    the container_scanner agent (monsys's frontend authenticates to this API
    with that agent's key to launch scans on behalf of its own users - it IS
    the scanning system's identity, not a telemetry-only sensor) may
    initiate scans or read platform-wide scan history/stats. Every other
    agent type (camera/drone/plc/robot/iot) is telemetry-only and must not
    be able to launch scans or read other assets' scan data.
    """
    def decorated(*args, **kwargs):
        if session.get('authenticated'):
            return f(*args, **kwargs)

        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({"error": "API Key is missing", "details": "Include X-API-Key header"}), 401

        user = User.query.filter_by(api_key=hash_api_key(api_key), is_active=True).first()
        if user:
            request.agent_type = f"user_{user.role}"
            request.user_id = user.id
            return f(*args, **kwargs)

        agent = Agent.query.filter_by(api_key=hash_api_key(api_key)).first()
        if agent:
            if agent.agent_type == 'security_scanner':
                request.agent_type = agent.agent_type
                request.agent_id = agent.agent_id
                return f(*args, **kwargs)
            return jsonify({
                "error": "Forbidden",
                "details": "Agent credentials cannot access scan management endpoints"
            }), 403

        return jsonify({"error": "Invalid API Key", "details": "Key not found in database"}), 401

    decorated.__name__ = f.__name__
    return decorated

def wait_for_db():
    """Wait for database to be ready"""
    max_retries = 30
    for i in range(max_retries):
        try:
            with app.app_context():
                db.session.execute(text('SELECT 1'))
            print("✅ Database connection successful")
            return True
        except Exception as e:
            if i < max_retries - 1:
                print(f"⏳ Database not ready, retrying... ({i+1}/{max_retries})")
                time.sleep(2)
            else:
                print(f"❌ Database connection failed: {e}")
                return False

# Initialize database - FIXED for unified schema
def init_database():
    with app.app_context():
        if wait_for_db():
            try:
                # Create tables based on models
                db.create_all()
                print("✅ Database tables created successfully")

                # Create default admin user if not exists.
                # The initial password comes from ADMIN_INITIAL_PASSWORD - if
                # that isn't set, a random one is generated and printed once
                # (there is no hardcoded fallback password).
                admin_user = User.query.filter_by(username='admin').first()
                if not admin_user:
                    initial_password = os.environ.get('ADMIN_INITIAL_PASSWORD')
                    generated_password = False
                    if not initial_password:
                        initial_password = secrets.token_urlsafe(16)
                        generated_password = True

                    admin_user = User(
                        username='admin',
                        role='admin',
                        email='admin@security.com'
                    )
                    admin_user.set_password(initial_password)
                    # generate_api_key() stores only the key's hash on the
                    # model and returns the raw key - the raw value is only
                    # ever available here, right after generation.
                    raw_admin_api_key = admin_user.generate_api_key()
                    try:
                        db.session.add(admin_user)
                        db.session.commit()
                        print("✅ Admin user created")
                        if generated_password:
                            print(f"🔑 Generated initial admin password (shown once, store it now): {initial_password}")
                        print(f"🔑 Admin API Key (shown once, store it now): {raw_admin_api_key}")
                    except IntegrityError:
                        # Lost the race against another worker process creating
                        # the same row concurrently - that's fine, it exists now.
                        db.session.rollback()
                        print("ℹ️ Admin user already created by another worker, skipping")

                # Βεβαιωθείτε ότι οι agents υπάρχουν στη βάση.
                # API keys are only ever generated (and printed) once, at
                # creation time - an existing agent's key is never
                # overwritten with a fixed/known value.
                agents_seed = [
                    {
                        'agent_id': 'Robot_Arm_001',
                        'agent_type': 'robot_agent',
                        'location': 'WMS_Zone_A_Picking',
                    },
                    {
                        'agent_id': 'DRONE-01',
                        'agent_type': 'drone_agent',
                        'location': 'Outdoor_Yard_Zone_B',
                    },
                    {
                        'agent_id': 'CAM-WH-01',
                        'agent_type': 'camera_agent',
                        'location': 'Warehouse Zone A - Entrance',
                    },
                    {
                        'agent_id': 'raspberrypi-01',
                        'agent_type': 'iot_agent',
                        'location': 'Control Room',
                    },
                    {
                        'agent_id': 'PLC001',
                        'agent_type': 'plc_agent',
                        'location': 'Warehouse_Main_Line_1',
                    },
                    {
                        'agent_id': 'container_scanner',
                        'agent_type': 'security_scanner',
                        'location': 'Security VM',
                        # Unlike every other agent here, this key is also
                        # needed by monsys - a *separate* deployment on
                        # another VM (see monsys/.env's SCANNER_API_KEY) -
                        # which can't read it from these logs. Rather than
                        # relying on copy-pasting a randomly generated value
                        # out of the backend's startup logs into monsys's
                        # .env by hand, let the operator provision ONE value
                        # in both places via CONTAINER_SCANNER_API_KEY. If
                        # unset, this still falls back to the same
                        # generate-once-and-print behavior as every other
                        # agent - it just can't be "transparently" shared
                        # with monsys in that case.
                        'api_key_override': os.environ.get('CONTAINER_SCANNER_API_KEY'),
                    }
                ]

                for agent_data in agents_seed:
                    try:
                        override_key = agent_data.get('api_key_override')
                        agent = Agent.query.filter_by(agent_id=agent_data['agent_id']).first()
                        if not agent:
                            agent = Agent(
                                agent_id=agent_data['agent_id'],
                                agent_type=agent_data['agent_type'],
                                location=agent_data['location'],
                            )
                            if override_key:
                                # Operator-provisioned value (shared with
                                # monsys) - store only its hash, same as
                                # generate_api_key() would.
                                agent.api_key = hash_api_key(override_key)
                                db.session.add(agent)
                                db.session.commit()
                                print(f"✅ Created agent: {agent_data['agent_id']}")
                                print(f"🔑 {agent_data['agent_id']} API Key set from CONTAINER_SCANNER_API_KEY (shared with monsys)")
                            else:
                                # generate_api_key() stores only the key's
                                # hash on the model and returns the raw key.
                                raw_agent_key = agent.generate_api_key()
                                db.session.add(agent)
                                db.session.commit()
                                print(f"✅ Created agent: {agent_data['agent_id']}")
                                print(f"🔑 {agent_data['agent_id']} API Key (shown once, store it now): {raw_agent_key}")
                        else:
                            # Keep agent_type/location in sync.
                            changed = False
                            if agent.agent_type != agent_data['agent_type']:
                                agent.agent_type = agent_data['agent_type']
                                changed = True
                            if agent.location != agent_data['location']:
                                agent.location = agent_data['location']
                                changed = True
                            if override_key:
                                # An explicit shared value always wins, so
                                # rotating CONTAINER_SCANNER_API_KEY and
                                # restarting keeps this agent's key in sync
                                # with monsys without touching the database
                                # by hand. (Every other agent's api_key is
                                # never overwritten once set - see the
                                # backfill-only branch below.)
                                new_hash = hash_api_key(override_key)
                                if agent.api_key != new_hash:
                                    agent.api_key = new_hash
                                    changed = True
                                    print(f"🔑 {agent_data['agent_id']} API Key synced from CONTAINER_SCANNER_API_KEY (shared with monsys)")
                            elif not agent.api_key:
                                # No override configured and the row has no
                                # key yet (e.g. it was pre-created by a
                                # placeholder INSERT in unified_schema.sql) -
                                # backfill a random one and print it once.
                                raw_agent_key = agent.generate_api_key()
                                changed = True
                                print(f"🔑 {agent_data['agent_id']} API Key (backfilled, shown once, store it now): {raw_agent_key}")
                            if changed:
                                db.session.commit()
                    except IntegrityError:
                        db.session.rollback()
                        print(f"ℹ️ Agent {agent_data['agent_id']} already created by another worker, skipping")

                # Check agents count
                agents_count = Agent.query.count()
                print(f"✅ Found {agents_count} agents in database")

            except Exception as e:
                print(f"❌ Database initialization error: {e}")
                db.session.rollback()
        else:
            print("⚠️ Skipping database initialization - database not available")

# Initialize the database when the app starts
init_database()

# ==================== CORS MIDDLEWARE ====================
@app.after_request
def after_request(response):
    """Add CORS headers to all responses"""
    origin = request.headers.get('Origin', '')
    allowed_origins = ['http://192.168.56.30:3000', 'http://localhost:3000']

    if origin in allowed_origins:
        response.headers.add('Access-Control-Allow-Origin', origin)
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, X-API-Key, Authorization, Accept, X-CSRF-Token')
        response.headers.add('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        response.headers.add('Access-Control-Max-Age', '3600')

    return response

@app.route('/')
def index():
    return """
    <html>
    <head>
        <title>Security System</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .container { max-width: 800px; margin: 0 auto; }
            .card { background: #f5f5f5; padding: 20px; margin: 10px 0; border-radius: 5px; }
            a { color: #0066cc; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🚀 Industrial Security System</h1>
            <div class="card">
                <h3>System Status: <span style="color: green;">✅ OPERATIONAL</span></h3>
                <p>Industrial IoT Security Monitoring Platform</p>
            </div>

            <h2>📊 Quick Access</h2>
            <div class="card">
                <h4>👁️ Monitoring</h4>
                <ul>
                    <li><a href="/dashboard">System Dashboard</a></li>
                    <li><a href="/health">Health Status</a></li>
                    <li><a href="/api/agents">Connected Agents</a></li>
                    <li><a href="/api/alerts">Active Alerts</a></li>
                    <li><a href="/api/telemetry">Telemetry Data</a></li>
                </ul>
            </div>

            <div class="card">
                <h4>🔑 API Access</h4>
                <p><strong>API Key required for protected endpoints</strong></p>
                <ul>
                    <li><code>/api/agents</code> - List all agents</li>
                    <li><code>/api/telemetry</code> - System metrics</li>
                    <li><code>/api/alerts</code> - Security alerts</li>
                </ul>
            </div>

            <div class="card">
                <h4>🔍 Security Scanner</h4>
                <p><strong>Frontend Security Scanner Interface</strong></p>
                <ul>
                    <li><a href="/api/security-scanner/health">Scanner Health</a></li>
                    <li><a href="/api/security-scanner/scan">Start Scan (POST)</a></li>
                    <li><a href="/api/security-scanner/history">Scan History</a></li>
                    <li><a href="/api/security-scanner/stats">Scanner Stats</a></li>
                </ul>
            </div>
        </div>
    </body>
    </html>
    """

@app.route('/dashboard')
def dashboard():
    """Real dashboard with actual metrics"""
    try:
        total_agents = Agent.query.count()
        active_alerts = Alert.query.filter_by(resolved=False).count()

        return jsonify({
            "system": "Industrial Security System",
            "status": "operational",
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": {
                "agents_connected": total_agents,  # ΠΡΑΓΜΑΤΙΚΟ
                "active_alerts": active_alerts,    # ΠΡΑΓΜΑΤΙΚΟ
                "database_status": "connected",
                "last_updated": datetime.utcnow().isoformat()
            }
        })
    except Exception as e:
        return jsonify({
            "system": "Industrial Security System",
            "status": "degraded",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }), 500


# ==================== API ENDPOINTS ====================

@app.route('/health', methods=['GET'])
def health_check():
    try:
        with app.app_context():
            db.session.execute(text('SELECT 1'))
            database_status = 'healthy'
    except Exception as e:
        database_status = f'unhealthy: {str(e)}'

    # Add Flower health check
    try:
        import requests
        response = requests.get(f"{FLOWER_URL}/api/workers",
                              auth=(FLOWER_USERNAME, FLOWER_PASSWORD),
                              timeout=5)
        flower_status = 'healthy' if response.status_code == 200 else f'unhealthy: {response.status_code}'
    except Exception as e:
        flower_status = f'unavailable: {str(e)}'

    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "database": database_status,
        "flower_monitoring": flower_status,
        "version": "1.0.0"
    })

@app.route('/api/agents', methods=['GET'])
@require_api_key
def get_agents():
    try:
        agents = Agent.query.all()
        return jsonify({
            "agents": [
                {
                    "id": agent.agent_id,
                    "type": agent.agent_type,
                    "agent_type": agent.agent_type,
                    "status": agent.status,
                    "location": agent.location,
                    "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
                    "created_at": agent.created_at.isoformat() if agent.created_at else None
                }
                for agent in agents
            ]
        })
    except Exception as e:
        return jsonify({"error": str(e), "agents": []}), 500

@app.route('/api/telemetry', methods=['GET'])
@require_api_key
def get_telemetry():
    try:
        # Get recent telemetry data
        telemetry = Telemetry.query.order_by(Telemetry.timestamp.desc()).limit(50).all()
        return jsonify({
            "telemetry": [
                {
                    "id": t.id,
                    "agent_id": t.agent.agent_id if t.agent else None,
                    "timestamp": t.timestamp.isoformat(),
                    "security_score": t.security_score,
                    "metrics": t.get_metrics(),
                    "anomalies": t.get_anomalies()
                }
                for t in telemetry
            ]
        })
    except Exception as e:
        return jsonify({"error": str(e), "telemetry": []}), 500

@app.route('/api/alerts', methods=['GET'])
@require_api_key
def get_alerts():
    try:
        alerts = Alert.query.filter_by(resolved=False).order_by(Alert.timestamp.desc()).limit(20).all()
        return jsonify({
            "alerts": [
                {
                    "id": alert.id,
                    "severity": alert.severity,
                    "message": alert.message,
                    "timestamp": alert.timestamp.isoformat(),
                    "agent_id": alert.agent_id,
                    "resolved": alert.resolved
                }
                for alert in alerts
            ]
        })
    except Exception as e:
        return jsonify({"error": str(e), "alerts": []}), 500

@app.route('/api/telemetry', methods=['POST'])
@require_api_key
def receive_telemetry():
    try:
        data = request.json
        agent_id = data.get('agent_id')
        metrics = data.get('metrics', {})
        security_score = data.get('security_score', 100)
        anomalies = data.get('anomalies', [])

        # Βρείτε τον agent βάσει του agent_id
        agent = Agent.query.filter_by(agent_id=agent_id).first()
        if not agent:
            return jsonify({"error": f"Agent not found: {agent_id}"}), 404

        # Ενημερώστε το last_seen
        agent.last_seen = datetime.utcnow()

        # Αποθηκεύστε το telemetry στη βάση
        telemetry = Telemetry(
            agent_id=agent.id,
            metrics=json.dumps(metrics),
            security_score=security_score,
            anomalies=json.dumps(anomalies),
            timestamp=datetime.utcnow()
        )
        db.session.add(telemetry)
        db.session.commit()

        print(f"✅ Telemetry received from {agent_id} - Score: {security_score}")
        return jsonify({"status": "success", "message": "Telemetry received"})

    except Exception as e:
        db.session.rollback()
        print(f"❌ Error receiving telemetry: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/stats', methods=['GET'])
@require_api_key
def get_stats():
    """Get system statistics"""
    try:
        total_agents = Agent.query.count()
        active_agents = Agent.query.filter_by(status='active').count()
        total_alerts = Alert.query.count()
        active_alerts = Alert.query.filter_by(resolved=False).count()
        total_telemetry = Telemetry.query.count()

        return jsonify({
            "total_agents": total_agents,
            "active_agents": active_agents,
            "total_alerts": total_alerts,
            "active_alerts": active_alerts,
            "total_telemetry": total_telemetry
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== TOPOLOGY ENDPOINT ====================

@app.route('/api/topology', methods=['GET'])
@require_api_key
def get_topology():
    """Get REAL topology data from database"""
    try:
        agents = Agent.query.all()

        # Transform agents for topology visualization
        topology_agents = []
        for agent in agents:
            # Get latest telemetry for security score
            latest_telemetry = Telemetry.query.filter_by(
                agent_id=agent.id
            ).order_by(Telemetry.timestamp.desc()).first()

            security_score = 100  # default
            if latest_telemetry:
                security_score = latest_telemetry.security_score

            # Determine status based on last_seen
            status = 'offline'
            if agent.last_seen:
                time_diff = (datetime.utcnow() - agent.last_seen).total_seconds()
                if time_diff < 300:  # 5 minutes
                    status = 'online'
                elif time_diff < 1800:  # 30 minutes
                    status = 'warning'
                else:
                    status = 'offline'
            else:
                status = 'unknown'

            topology_agents.append({
                'id': agent.agent_id,
                'agent_type': agent.agent_type,
                'status': status,
                'location': agent.location,
                'security_score': security_score,
                'last_seen': agent.last_seen.isoformat() if agent.last_seen else None,
                'created_at': agent.created_at.isoformat() if agent.created_at else None
            })

        return jsonify({
            'agents': topology_agents,
            'servers': [
                {
                    'id': 'backend-vm',
                    'type': 'security_server',
                    'status': 'online',
                    'ip_address': '192.168.56.20:15000',
                    'description': 'Security System Backend',
                    'security_score': 95
                },
                {
                    'id': 'frontend-vm',
                    'type': 'monitoring_server',
                    'status': 'online',
                    'ip_address': '192.168.56.30:3000',
                    'description': 'Monitoring Frontend Dashboard',
                    'security_score': 90
                }
            ],
            'total_connections': len(topology_agents),
            'online_connections': len([a for a in topology_agents if a['status'] == 'online']),
            'last_updated': datetime.utcnow().isoformat(),
            'system_status': 'operational'
        })

    except Exception as e:
        print(f"❌ Error in topology endpoint: {e}")
        import traceback
        traceback.print_exc()

        return jsonify({
            "error": str(e),
            "agents": [],
            "servers": [],
            "total_connections": 0,
            "online_connections": 0,
            "last_updated": datetime.utcnow().isoformat(),
            "system_status": "error"
        }), 500

# ==================== AUTHENTICATION ENDPOINTS ====================

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login endpoint for monitoring system"""
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        client_ip = request.remote_addr or 'unknown'
        rate_limit_key = f"{username}:{client_ip}"

        if is_login_locked_out(rate_limit_key):
            log_audit(None, 'login_locked_out', resource='auth', details=f"username={username}, ip={client_ip}")
            return jsonify({"error": "Too many failed login attempts. Try again later."}), 429

        # Βρείτε τον χρήστη
        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            record_failed_login(rate_limit_key)
            log_audit(user.id if user else None, 'login_failure', resource='auth',
                      details=f"username={username}, ip={client_ip}")
            return jsonify({"error": "Invalid credentials"}), 401

        if not user.is_active:
            log_audit(user.id, 'login_failure', resource='auth',
                      details=f"username={username}, ip={client_ip}, reason=inactive")
            return jsonify({"error": "Account is disabled"}), 403

        clear_failed_login(rate_limit_key)

        # Ενημερώστε last_login
        user.last_login = datetime.utcnow()
        db.session.commit()

        # Set session for frontend authentication
        session['authenticated'] = True
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
        session['csrf_token'] = secrets.token_urlsafe(32)

        log_audit(user.id, 'login_success', resource='auth', details=f"username={username}, ip={client_ip}")

        return jsonify({
            "status": "success",
            "user": {
                "id": user.id,
                "username": user.username,
                "role": user.role,
                "email": user.email
            },
            # Note: no api_key field here. Only its hash is stored server-side
            # (see models.hash_api_key) - the raw key is shown once, at
            # creation/regeneration time, and cannot be recovered afterwards.
            "csrf_token": session['csrf_token']
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Logout endpoint"""
    user_id = session.get('user_id')
    if user_id:
        log_audit(user_id, 'logout', resource='auth')
    session.clear()
    return jsonify({"status": "success", "message": "Logged out"})

@app.route('/api/auth/verify', methods=['GET'])
@require_api_key
def verify_auth():
    """Verify API key authentication"""
    agent_type = getattr(request, 'agent_type', 'unknown')
    agent_id = getattr(request, 'agent_id', None)
    user_id = getattr(request, 'user_id', None)

    return jsonify({
        "status": "success",
        "authenticated_as": agent_type,
        "agent_id": agent_id,
        "user_id": user_id,
        "timestamp": datetime.utcnow().isoformat()
    })

@app.route('/api/auth/session-check', methods=['GET'])
def session_check():
    """Check if user has valid session"""
    if session.get('authenticated'):
        return jsonify({
            "authenticated": True,
            "user": {
                "id": session.get('user_id'),
                "username": session.get('username'),
                "role": session.get('role')
            },
            "csrf_token": session.get('csrf_token')
        })
    return jsonify({"authenticated": False})

# ==================== TEST CELERY ENDPOINT ====================

@app.route('/api/test-celery', methods=['GET', 'POST'])
@require_api_key
def test_celery_endpoint():
    """Test endpoint to verify Celery is working"""
    if not CELERY_AVAILABLE:
        return jsonify({
            "status": "error",
            "message": "Celery module not available. Check celery_tasks.py"
        }), 500

    try:
        # Send test task
        task = test_celery_worker.delay()

        return jsonify({
            "status": "success",
            "message": "Celery test task sent",
            "task_id": task.id,
            "endpoint": "Check /api/v2/security/scans for actual scanning"
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Celery test failed: {str(e)}"
        }), 500

# ==================== FRONTEND SECURITY SCANNER ENDPOINTS ====================
# Αυτά τα endpoints καλεί το frontend (security scanner interface)

@app.route('/api/security-scanner/health', methods=['GET'])
def scanner_health():
    """Health check για το frontend security scanner"""
    try:
        if not CELERY_AVAILABLE:
            return jsonify({
                "status": "unavailable",
                "message": "Celery module not loaded",
                "scanner_status": "offline"
            }), 503

        # Check if Celery workers are available
        try:
            insp = celery_app.control.inspect()
            stats = insp.stats()
            celery_available = bool(stats)
            if stats:
                print(f"✅ Celery workers available: {list(stats.keys())}")
            else:
                print("⚠️  No Celery workers found")
        except Exception as e:
            print(f"⚠️  Could not inspect Celery workers: {e}")
            celery_available = False

        # Check Docker availability
        docker_available = False
        try:
            from celery_tasks import scanner
            if scanner and scanner.docker_client:
                docker_available = True
                print("✅ Docker client is available")
        except Exception as e:
            print(f"⚠️  Docker check failed: {e}")

        return jsonify({
            "status": "healthy" if celery_available and docker_available else "degraded",
            "celery_workers_available": celery_available,
            "docker_available": docker_available,
            "scanner_status": "online" if celery_available and docker_available else "offline",
            "timestamp": datetime.utcnow().isoformat(),
            "flower_url": FLOWER_URL
        })
    except Exception as e:
        print(f"❌ Scanner health check error: {e}")
        return jsonify({
            "status": "degraded",
            "message": str(e),
            "scanner_status": "offline"
        }), 503

@app.route('/api/security-scanner/scan', methods=['POST'])
@require_frontend_auth
@require_csrf
def start_frontend_scan():
    """Initiate scan from frontend - ΑΠΛΟΠΟΙΗΜΕΝΟ"""
    if not CELERY_AVAILABLE:
        return jsonify({"error": "Scanner system not available", "details": "Celery not loaded"}), 503

    try:
        data = request.json
        scan_type = data.get('scan_type', 'nmap')
        target = data.get('target')

        print(f"🎯 Received scan request: type={scan_type}, target={target}")

        if not target:
            return jsonify({"error": "Target is required"}), 400

        # Validate target format
        if not validate_target(target):
            return jsonify({"error": "Invalid target format"}), 400

        # Initiate appropriate scan with Celery
        task_id = None
        if scan_type == 'nmap':
            scan_options = data.get('options', {}).get('nmap_options', "-sV -sC")
            if not validate_nmap_options(scan_options):
                return jsonify({"error": "Invalid nmap options"}), 400
            print(f"🚀 Starting nmap scan: {target}")
            task = nmap_scan_task.delay(target, scan_options)
            task_id = task.id

        elif scan_type == 'nuclei':
            template_type = data.get('options', {}).get('template_type', 'cves')
            if not validate_nuclei_template(template_type):
                return jsonify({"error": "Invalid nuclei template type"}), 400
            print(f"🚀 Starting nuclei scan: {target}")
            task = nuclei_scan_task.delay(target, template_type)
            task_id = task.id

        elif scan_type == 'comprehensive':
            print(f"🚀 Starting comprehensive scan: {target}")
            task = comprehensive_scan_task.delay(target)
            task_id = task.id

        else:
            return jsonify({"error": f"Unknown scan type: {scan_type}"}), 400

        print(f"✅ Scan task submitted: {task_id}")

        return jsonify({
            "task_id": task_id,
            "status": "started",
            "scan_type": scan_type,
            "target": target,
            "message": f"Security scan initiated successfully",
            "timestamp": datetime.utcnow().isoformat()
        })

    except Exception as e:
        print(f"❌ Error starting scan: {e}")
        return jsonify({"error": f"Failed to start scan: {str(e)}"}), 500

@app.route('/api/security-scanner/status/<task_id>', methods=['GET'])
@require_frontend_auth
def get_frontend_scan_status(task_id):
    """Get scan status for frontend - ΧΡΗΣΙΜΟΠΟΙΕΙ ΤΟ ΙΔΙΟ task_id"""
    print(f"📊 Backend: Frontend asking for task {task_id}")

    if not CELERY_AVAILABLE:
        return jsonify({"error": "Scanner system not available"}), 503

    try:
        from celery.result import AsyncResult

        task_result = AsyncResult(task_id, app=celery_app)
        print(f"📊 Backend: Celery state for {task_id}: {task_result.state}")

        response = {
            'task_id': task_id,
            'state': task_result.state,
            'timestamp': datetime.utcnow().isoformat()
        }

        if task_result.state == 'PENDING':
            response['status'] = 'Task is pending execution'
            response['progress'] = 10

        elif task_result.state == 'PROGRESS':
            if task_result.info:
                response['status'] = task_result.info.get('status', 'Task is in progress')
                response['progress'] = task_result.info.get('progress', 50)
            else:
                response['status'] = 'Task is in progress'
                response['progress'] = 50

        elif task_result.state == 'SUCCESS':
            response['status'] = 'Task completed successfully'
            response['progress'] = 100

            # Προσθέτουμε όλα τα δεδομένα
            result_data = task_result.result
            if isinstance(result_data, dict):
                response['result'] = result_data
            else:
                response['result'] = {'raw_data': str(result_data)}

        elif task_result.state == 'FAILURE':
            response['status'] = 'Task failed'
            response['progress'] = 100
            response['error'] = str(task_result.info) if task_result.info else 'Unknown error'

        else:
            response['status'] = f'Task state: {task_result.state}'
            response['progress'] = 30

        print(f"📊 Backend: Sending response for {task_id}: {response.get('state')}")
        return jsonify(response)

    except Exception as e:
        print(f"❌ Backend Error getting task status: {e}")
        return jsonify({"error": str(e), "task_id": task_id}), 500

@app.route('/api/security-scanner/history', methods=['GET'])
@require_frontend_auth
def get_frontend_scan_history():
    """Get recent security scan history for frontend - ΑΠΟ POSTGRESQL!"""
    conn = None
    cursor = None
    try:
        DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://admin:password@localhost:5432/security_db')
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()

        # Query the security_scans table
        cursor.execute('''
            SELECT id, tool, target, success, created_at, results::text
            FROM security_scans
            ORDER BY created_at DESC
            LIMIT 20
        ''')

        scans = []
        for row in cursor.fetchall():
            try:
                results = json.loads(row[5]) if row[5] else {}

                # Extract vulnerabilities count
                vuln_count = 0
                if isinstance(results, dict):
                    vuln_count = results.get('vulnerabilities_found', 0)
                    if not vuln_count and results.get('vulnerabilities'):
                        vuln_count = len(results.get('vulnerabilities', []))

                scans.append({
                    'id': row[0],
                    'tool': row[1],
                    'target': row[2],
                    'success': row[3],
                    'timestamp': row[4].isoformat() if row[4] else None,
                    'vulnerabilities_found': vuln_count,
                    'duration_seconds': results.get('duration_seconds', 0) if isinstance(results, dict) else 0,
                    'has_results': bool(results)
                })
            except json.JSONDecodeError:
                scans.append({
                    'id': row[0],
                    'tool': row[1],
                    'target': row[2],
                    'success': row[3],
                    'timestamp': row[4].isoformat() if row[4] else None,
                    'vulnerabilities_found': 0,
                    'duration_seconds': 0,
                    'has_results': False
                })

        return jsonify({
            "scans": scans,
            "total": len(scans),
            "timestamp": datetime.utcnow().isoformat()
        })

    except Exception as e:
        print(f"❌ Error getting scan history: {e}")
        return jsonify({"error": str(e), "scans": []}), 500
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except Exception:
                pass
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

@app.route('/api/security-scanner/stats', methods=['GET'])
@require_frontend_auth
def get_frontend_scanner_stats():
    """Get security scanning statistics for frontend"""
    conn = None
    cursor = None
    try:
        DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://admin:password@localhost:5432/security_db')
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()

        # Total scans
        cursor.execute("SELECT COUNT(*) FROM security_scans")
        total_scans = cursor.fetchone()[0] or 0

        # Successful scans
        cursor.execute("SELECT COUNT(*) FROM security_scans WHERE success = true")
        successful_scans = cursor.fetchone()[0] or 0

        # Scans by tool
        cursor.execute("SELECT tool, COUNT(*) FROM security_scans GROUP BY tool")
        scans_by_tool = {row[0]: row[1] for row in cursor.fetchall()}

        # Total vulnerabilities found
        cursor.execute('''
            SELECT SUM(
                CASE
                    WHEN results::text LIKE '%vulnerabilities_found%'
                    THEN (results::jsonb->>'vulnerabilities_found')::int
                    ELSE 0
                END
            ) FROM security_scans WHERE success = true
        ''')
        total_vulnerabilities = cursor.fetchone()[0] or 0

        # Recent scans (last 24 hours)
        cursor.execute('''
            SELECT COUNT(*) FROM security_scans
            WHERE created_at > NOW() - INTERVAL '24 hours'
        ''')
        scans_24h = cursor.fetchone()[0] or 0

        success_rate = round((successful_scans / total_scans * 100), 2) if total_scans > 0 else 0

        return jsonify({
            "total_scans": total_scans,
            "successful_scans": successful_scans,
            "failed_scans": total_scans - successful_scans,
            "total_vulnerabilities": total_vulnerabilities,
            "scans_by_tool": scans_by_tool,
            "scans_24h": scans_24h,
            "success_rate": success_rate,
            "system_status": "operational" if total_scans > 0 else "no_scans_yet",
            "timestamp": datetime.utcnow().isoformat()
        })

    except Exception as e:
        print(f"❌ Error getting scanner stats: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except Exception:
                pass
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

@app.route('/api/security-scanner/tools', methods=['GET'])
@require_frontend_auth
def get_frontend_tools():
    """Get available scanning tools info"""
    return jsonify({
        "available_tools": [
            {
                "name": "nmap",
                "description": "Network discovery and security auditing",
                "scan_types": ["port_scan", "service_detection", "vulnerability_scan"],
                "default_options": "-sV -sC",
                "container_image": "instrumentisto/nmap"
            },
            {
                "name": "nuclei",
                "description": "Fast and customizable vulnerability scanner",
                "scan_types": ["cves", "exposed_panels", "security_misconfigurations"],
                "default_options": "-t cves",
                "container_image": "projectdiscovery/nuclei"
            },
            {
                "name": "comprehensive",
                "description": "Combined nmap + nuclei scan",
                "scan_types": ["full_scan"],
                "container_images": ["instrumentisto/nmap", "projectdiscovery/nuclei"]
            }
        ],
        "containerized": True,
        "celery_available": CELERY_AVAILABLE,
        "flower_monitoring": FLOWER_URL,
        "timestamp": datetime.utcnow().isoformat()
    })

# Προσθέτω την validate_target method ως instance method (backward compat)
app.validate_target = validate_target

# ==================== V2 SECURITY SCANNING ENDPOINTS (API Key) ====================

@app.route('/api/v2/security/scans', methods=['POST'])
@require_scan_access
def create_security_scan():
    """Initiate new security scan - Containerized scanning (API Key, User accounts only)"""
    if not CELERY_AVAILABLE:
        return jsonify({"error": "Celery scanning system not available"}), 503

    try:
        data = request.json
        scan_type = data.get('scan_type', 'comprehensive')
        target = data.get('target')
        scan_options = data.get('scan_options', "")

        if not target:
            return jsonify({"error": "Target is required"}), 400

        if not validate_target(target):
            return jsonify({"error": "Invalid target format"}), 400

        # Initiate appropriate scan
        if scan_type == 'nmap':
            if scan_options and not validate_nmap_options(scan_options):
                return jsonify({"error": "Invalid nmap options"}), 400
            task = nmap_scan_task.delay(target, scan_options or "-sV -sC")
        elif scan_type == 'nuclei':
            template_type = data.get('template_type', 'cves')
            if not validate_nuclei_template(template_type):
                return jsonify({"error": "Invalid nuclei template type"}), 400
            task = nuclei_scan_task.delay(target, template_type)
        else:  # comprehensive
            task = comprehensive_scan_task.delay(target)

        return jsonify({
            "task_id": task.id,
            "status": "started",
            "scan_type": scan_type,
            "target": target,
            "message": "Security scan initiated successfully"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/v2/security/scans/<task_id>', methods=['GET'])
@require_scan_access
def get_scan_status(task_id):
    """Get status of security scan task (API Key, User accounts only)"""
    if not CELERY_AVAILABLE:
        return jsonify({"error": "Celery scanning system not available"}), 503

    try:
        # Use Celery's AsyncResult to get task status
        from celery.result import AsyncResult

        task_result = AsyncResult(task_id, app=celery_app)

        if task_result.state == 'PENDING':
            response = {
                'state': task_result.state,
                'status': 'Task is pending execution'
            }
        elif task_result.state == 'PROGRESS':
            response = {
                'state': task_result.state,
                'status': 'Task is in progress',
                'info': task_result.info.get('status', 'Processing') if task_result.info else 'Processing'
            }
        elif task_result.state == 'SUCCESS':
            response = {
                'state': task_result.state,
                'status': 'Task completed successfully',
                'result': task_result.result
            }
        elif task_result.state == 'FAILURE':
            response = {
                'state': task_result.state,
                'status': 'Task failed',
                'error': str(task_result.info) if task_result.info else 'Unknown error'
            }
        else:
            response = {
                'state': task_result.state,
                'status': f'Task state: {task_result.state}'
            }

        return jsonify(response)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/v2/security/history', methods=['GET'])
@require_scan_access
def get_scan_history():
    """Get recent security scan history (API Key, User accounts only)"""
    conn = None
    cursor = None
    try:
        DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://admin:password@localhost:5432/security_db')
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()

        # Query the security_scans table
        cursor.execute('''
            SELECT id, tool, target, success, created_at
            FROM security_scans
            ORDER BY created_at DESC
            LIMIT 20
        ''')

        scans = []
        for row in cursor.fetchall():
            scans.append({
                'id': row[0],
                'tool': row[1],
                'target': row[2],
                'success': row[3],
                'created_at': row[4].isoformat() if row[4] else None
            })

        return jsonify({
            "scans": scans,
            "total": len(scans)
        })

    except Exception as e:
        return jsonify({"error": str(e), "scans": []}), 500
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except Exception:
                pass
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

@app.route('/api/v2/security/stats', methods=['GET'])
@require_scan_access
def get_security_stats():
    """Get security scanning statistics (API Key, User accounts only)"""
    conn = None
    cursor = None
    try:
        DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://admin:password@localhost:5432/security_db')
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()

        # Total scans
        cursor.execute("SELECT COUNT(*) FROM security_scans")
        total_scans = cursor.fetchone()[0]

        # Successful scans
        cursor.execute("SELECT COUNT(*) FROM security_scans WHERE success = true")
        successful_scans = cursor.fetchone()[0]

        # Scans by tool
        cursor.execute("SELECT tool, COUNT(*) FROM security_scans GROUP BY tool")
        scans_by_tool = {row[0]: row[1] for row in cursor.fetchall()}

        # Recent vulnerabilities found
        cursor.execute('''
            SELECT COUNT(*) FROM security_scans
            WHERE success = true AND results::text LIKE '%vulnerable%'
        ''')
        vulnerabilities_found = cursor.fetchone()[0]

        return jsonify({
            "total_scans": total_scans,
            "successful_scans": successful_scans,
            "failed_scans": total_scans - successful_scans,
            "vulnerabilities_found": vulnerabilities_found,
            "scans_by_tool": scans_by_tool,
            "success_rate": round((successful_scans / total_scans * 100), 2) if total_scans > 0 else 0
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except Exception:
                pass
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

@app.route('/api/v2/security/tools', methods=['GET'])
@require_api_key
def get_available_tools():
    """Get list of available security scanning tools (API Key)"""
    return jsonify({
        "available_tools": [
            {
                "name": "nmap",
                "description": "Network discovery and security auditing",
                "scan_types": ["network_scan", "service_detection", "vulnerability_scan"]
            },
            {
                "name": "nuclei",
                "description": "Fast and customizable vulnerability scanner",
                "scan_types": ["cves", "exposed_panels", "security_misconfigurations"]
            }
        ],
        "containerized": True,
        "status": "available" if CELERY_AVAILABLE else "unavailable"
    })

@app.route('/api/v2/security/health', methods=['GET'])
@require_api_key
def container_scanning_health():
    """Health check for containerized scanning system (API Key)"""
    if not CELERY_AVAILABLE:
        return jsonify({
            "status": "unavailable",
            "message": "Celery module not loaded",
            "container_scanning": "unavailable"
        }), 503

    try:
        # Check if Celery workers are available
        insp = celery_app.control.inspect()
        stats = insp.stats()

        # Check Docker availability
        from celery_tasks import scanner
        docker_available = scanner.docker_client is not None

        return jsonify({
            "status": "healthy",
            "celery_workers_available": bool(stats),
            "docker_available": docker_available,
            "container_scanning": "available",
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({
            "status": "degraded",
            "message": str(e),
            "container_scanning": "unavailable"
        }), 503

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=15000, debug=True)
