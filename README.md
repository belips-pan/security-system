
# SECURITY-SYSTEM BACKEND- Industrial IoT Security Monitoring Platform 🛡️

<https://img.shields.io/badge/Architecture-Microservices-blue>  
<https://img.shields.io/badge/Docker-Containers-2496ED>  
<https://img.shields.io/badge/Database-PostgreSQL-336791>  
<https://img.shields.io/badge/Python-3.9-3776AB>  
<https://img.shields.io/badge/License-MIT-green>

## 📋 Περίληψη Προγράμματος

**Security-System** είναι μια ολοκληρωμένη πλατφόρμα ασφαλείας για βιομηχανικά IoT συστήματα που παρέχει:

- Παρακολούθηση ασφαλείας σε πραγματικό χρόνο
- Σάρωση ευπάθειας (vulnerability scanning)
- Διαχείριση συμβάντων ασφαλείας
- Ενοποιημένο dashboard για όλα τα IoT agents

## 🏗️ Αρχιτεκτονική Συστήματος

```mermaid
flowchart TD
    subgraph "Frontend Layer (VM3)"
        A[React Dashboard - 192.168.56.30:3000]
    end

    subgraph "Application Layer"
        B[Backend API - Flask + Celery + PostgreSQL]
        C[Agents - Robot/Drone/Camera/IoT]
    end

    subgraph "Infrastructure Layer"
        D[Docker, Redis, Kafka, MQTT, PostgreSQL, Flower Monitoring]
    end

    A --> B
    A --> C
    B --> D
    C --> D
```	
	

## Services
- **Backend API** (Port 5000) - Flask REST API
- **PostgreSQL** (Port 5432) - Database
- **Kafka** (Port 9092) - Message broker
- **Zookeeper** (Port 2181) - Kafka coordination
- **Mosquitto MQTT** (Port 1883) - IoT messaging
- **Edge Gateway** - Message processing	

## 🚀 Γρήγορη Εκκίνηση

**Προαπαιτούμενα**

- Docker & Docker Compose
- Python 3.9+
- 8GB RAM minimum
- Ubuntu 20.04+ (προτείνεται)

**Εγκατάσταση σε 3 Βήματα**

bash

_\# 1. Κλώνος αποθήκης_

git clone <https://github.com/belips-pan/security-system.git>

cd security-system

_\# 2. Δημιουργία αρχείου environment_

cp .env.example .env

_\# Επεξεργασία του .env με τις τιμές σας_

_\# 3. Εκκίνηση συστήματος_

cd docker

chmod +x start-fast.sh

./start-fast.sh

**Εναλλακτική Εκκίνηση**

bash

_\# Πλήρης εκκίνηση (build από την αρχή)_

./docker/start.sh

_\# Μόνο βασικές υπηρεσίες_

docker-compose up -d postgres redis backend

## 🐳 Docker Services

| Service | Port | Description | Health Check |
| --- | --- | --- | --- |
| **Backend API** | 15000 | Flask REST API | <http://localhost:15000/health> |
| **PostgreSQL** | 15433 | Database | localhost:15433 |
| **Redis** | 16379 | Cache & Message Broker | redis-cli -p 16379 ping |
| **Kafka** | 19093 | Event Streaming | localhost:19093 |
| **MQTT Broker** | 1883 | IoT Messaging | mosquitto_sub -h localhost -t test |
| **Flower** | 15555 | Celery Monitoring | <http://localhost:15555> (admin:password) |

## 📊 Πρότυπο Δικτύου

yaml

networks:

monitoring-network:

ipam:

config:

\- subnet: 192.168.56.0/24

gateway: 192.168.56.1

**IP Addresses:**

- Backend VM: 192.168.56.20
- Agents VM: 192.168.56.10 (simulated)
- Frontend VM: 192.168.56.30

## 🔧 Δομή Project

text

security-system/

├── docker/ # Docker configurations

│ ├── docker-compose.yml # Main orchestration

│ ├── Dockerfile.backend # Backend image

│ ├── Dockerfile.celery # Celery worker image

│ ├── unified_schema.sql # Database schema

│ └── start-fast.sh # Quick startup script

├── src/

│ ├── backend/ # Core backend

│ │ ├── app.py # Flask application

│ │ ├── celery_tasks.py # Security scanning tasks

│ │ ├── models.py # Database models

│ │ └── auth.py # Authentication system

│ ├── agents/ # IoT Agents

│ │ ├── robot_agent.py # Industrial robot

│ │ ├── drone_agent.py # Security drone

│ │ ├── camera_agent.py # Surveillance camera

│ │ └── plc_agent.py # PLC controller

│ └── configs/ # Configuration files

│ └── \*.json # Agent configurations

└── scripts/ # Utility scripts

└── create_demo_data.py # Sample data generator

## 🔐 Αυθεντικοποίηση & API

**API Keys (Demo Environment)**

| Agent | Type | API Key |
| --- | --- | --- |
| Robot_Arm_001 | robot_agent | DVvkafojenj6091wusBSJbL02gIawkIFt2oS8rJIF4U |
| DRONE-01 | drone_agent | DWVkXiDJ_IIbdkxRTSIKjAhe4bFUuvhFgiMfWhaII |
| CAM-WH-01 | camera_agent | QIFDkxVGMQ0dzMnn90-GlqzBpMVr4425FRIYvAIyFTU |
| container_scanner | security_scanner | container_scan_123 |

**Χρήση API**

python

import requests

_\# Παράδειγμα αίτησης με API Key_

headers = {'X-API-Key': 'DVvkafojenj6091wusBSJbL02gIawkIFt2oS8rJIF4U'}

response = requests.post('<http://192.168.56.20:15000/api/telemetry>',

json=telemetry_data,

headers=headers)

**Endpoint Ομάδες**

**1\. Agent Communication**

- POST /api/telemetry - Αποστολή telemetry data
- GET /api/agents - Λίστα όλων των agents
- GET /api/alerts - Ενεργά security alerts

**2\. Security Scanner API**

- POST /api/security-scanner/scan - Εκκίνηση σάρωσης
- GET /api/security-scanner/status/{task_id} - Κατάσταση σάρωσης
- GET /api/security-scanner/history - Ιστορικό σαρώσεων

**3\. System Management**

- GET /health - Health check συστήματος
- GET /api/topology - Δικτυακή τοπολογία
- GET /dashboard - Συγκεντρωτικά στατιστικά

## 🔍 Security Scanner Features

**Διαθέσιμα Εργαλεία Σάρωσης**

| Tool | Description | Container Image |
| --- | --- | --- |
| **Nmap** | Network discovery & port scanning | instrumentisto/nmap |
| **Nuclei** | Vulnerability scanner | projectdiscovery/nuclei |
| **Comprehensive** | Combined Nmap + Nuclei scan | Both images |

**Παράδειγμα Σάρωσης**

bash

_\# REST API Call_

curl -X POST "<http://localhost:15000/api/security-scanner/scan>" \\

\-H "Content-Type: application/json" \\

\-H "X-API-Key: container_scan_123" \\

\-d '{

"scan_type": "nmap",

"target": "192.168.56.20",

"options": {

"nmap_options": "-sV -sC"

}

}'

**Παρακολούθηση Σαρώσεων**

bash

_\# 1. Monitor task status_

curl "<http://localhost:15000/api/security-scanner/status/{task_id}>"

_\# 2. View in Flower UI_

open <http://localhost:15555>

_\# Credentials: admin / password_

## 🤖 IoT Agents Configuration

**Υποστηριζόμενοι Τύποι Agents**

- **Robot Agent** - Βιομηχανικά ρομπότ
- **Drone Agent** - Drones μεταφορών/ασφαλείας
- **Camera Agent** - Κάμερες παρακολούθησης
- **IoT Agent** - Συσκευές IoT
- **PLC Agent** - Βιομηχανικοί ελεγκτές

**Παράδειγμα Ρύθμισης Agent**

json

{

"agent_id": "Robot_Arm_001",

"agent_type": "robot_agent",

"api_key": "DVvkafojenj6091wusBSJbL02gIawkIFt2oS8rJIF4U",

"location": "WMS_Zone_A_Picking",

"metrics": {

"command_anomalies": {

"unauthorized_source": {

"risk_points": 30

}

}

}

}

## 📊 Database Schema

**Βασικοί Πίνακες**

sql

_\-- Ενιαίο schema για όλο το σύστημα_

CREATE TABLE agents (

id SERIAL PRIMARY KEY,

agent_id VARCHAR(50) UNIQUE,

agent_type VARCHAR(50),

location VARCHAR(100),

api_key VARCHAR(64) UNIQUE

);

CREATE TABLE telemetry (

id SERIAL PRIMARY KEY,

agent_id INTEGER REFERENCES agents(id),

security_score INTEGER,

metrics JSONB,

timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);

CREATE TABLE security_scans (

id SERIAL PRIMARY KEY,

tool VARCHAR(50),

target VARCHAR(255),

results JSONB,

success BOOLEAN,

created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);

**Δημιουργία Demo Data**

bash

_\# Δημιουργία δοκιμαστικών δεδομένων_

python scripts/create_demo_data.py

_\# Έξοδος:_

_\# ✅ Demo database created successfully!_

_\# 📊 Statistics: 2 users, 6 agents, 144 telemetry records, 4 alerts_

**🔧 Ανάπτυξη & Development**

**Local Development Setup**

bash

_\# 1. Create virtual environment_

python -m venv venv

source venv/bin/activate _\# Linux/Mac_

_\# ή venv\\Scripts\\activate # Windows_

_\# 2. Install dependencies_

pip install -r src/backend/requirements.txt

pip install -r src/backend/requirements-celery.txt

_\# 3. Start services_

cd docker

docker-compose up -d postgres redis

_\# 4. Run backend locally_

cd ../src/backend

export DATABASE_URL="postgresql://admin:password@localhost:15433/security_db"

export REDIS_URL="redis://localhost:16379/0"

python app.py

**Testing**

bash

_\# Health checks_

./docker/check.sh

_\# Test endpoints_

curl <http://localhost:15000/health>

curl <http://localhost:15000/api/agents>

_\# Test Celery_

docker-compose exec backend python -c "

from celery_tasks import test_celery_worker

task = test_celery_worker.delay()

print(f'Task ID: {task.id}')

"

## 🐛 Αντιμετώπιση Προβλημάτων

**Συχνά Προβλήματα**

| Πρόβλημα | Λύση |
| --- | --- |
| Database connection failed | docker-compose restart postgres |
| Celery workers not responding | docker-compose restart celery-worker |
| Docker permission denied | sudo chmod 666 /var/run/docker.sock |
| Port already in use | Αλλάξτε ports στο .env |

**Logs & Debugging**

bash

_\# Προβολή logs_

docker-compose logs -f backend

docker-compose logs -f celery-worker

_\# Ειδικοί έλεγχοι_

docker-compose exec backend python -c "from container_scanner import ContainerSecurityScanner; s = ContainerSecurityScanner(); print(f'Docker available: {s.docker_client is not None}')"

## 📈 Monitoring & Observability

**Εργαλεία Παρακολούθησης**

- **Flower Dashboard**: <http://localhost:15555>
  - Κατάσταση Celery workers
  - Task queue monitoring
  - Worker statistics
- **API Health Endpoints**:

bash

curl <http://localhost:15000/health>

curl <http://localhost:15000/api/security-scanner/health>

- **Database Metrics**:

sql

_\-- PostgreSQL statistics_

SELECT COUNT(\*) as total_agents FROM agents;

SELECT AVG(security_score) as avg_security_score FROM telemetry;

**Custom Metrics**

python

_\# Προσθήκη custom metrics στο app.py_

@app.route('/api/metrics/custom')

def custom_metrics():

return jsonify({

"agents_by_type": get_agents_by_type(),

"alerts_by_severity": get_alerts_by_severity(),

"scan_success_rate": get_scan_success_rate()

})

## 🔄 Workflow Examples

**1\. Πλήρης Σάρωση Συστήματος**

python

import requests

import time

def comprehensive_security_scan(target):

_\# 1. Start scan_

response = requests.post(

"<http://localhost:15000/api/security-scanner/scan>",

json={"scan_type": "comprehensive", "target": target},

headers={"X-API-Key": "container_scan_123"}

)

task_id = response.json()\["task_id"\]

_\# 2. Monitor progress_

while True:

status = requests.get(

f"<http://localhost:15000/api/security-scanner/status/{task_id}>"

).json()

if status\["state"\] == "SUCCESS":

return status\["result"\]

elif status\["state"\] == "FAILURE":

raise Exception(f"Scan failed: {status.get('error')}")

time.sleep(5)

**2\. Αυτόματη Παρακολούθηση Agents**

python

def monitor_agents():

agents = requests.get(

"<http://localhost:15000/api/agents>",

headers={"X-API-Key": "admin_api_key"}

).json()\["agents"\]

for agent in agents:

if agent\["status"\] != "active":

send_alert(f"Agent {agent\['id'\]} is {agent\['status'\]}")

## 📚 API Documentation

**OpenAPI/Swagger**

yaml

_\# Πρόσθεσε στο app.py_

from flask_swagger_ui import get_swaggerui_blueprint

SWAGGER_URL = '/api/docs'

API_URL = '/swagger.json'

swaggerui_blueprint = get_swaggerui_blueprint(

SWAGGER_URL,

API_URL,

config={'app_name': "Security System API"}

)

app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

**API Response Examples**

json

{

"agent_telemetry": {

"endpoint": "POST /api/telemetry",

"request": {

"agent_id": "Robot_Arm_001",

"security_score": 85,

"metrics": {"cpu_usage": 45, "memory_usage": 60}

},

"response": {

"status": "success",

"message": "Telemetry received"

}

}

}

## 🏆 Best Practices

**Security Recommendations**

- **Αλλαγή Προεπιλεγμένων Κωδικών** στο .env
- **Χρήση HTTPS** σε production
- **Rate Limiting** για API endpoints
- **Κανονική ενημέρωση** Docker images
- **Backup** της βάσης δεδομένων

**Performance Tips**

- Χρήση Redis cache για συχνά δεδομένα
- Connection pooling για PostgreSQL
- Προσαρμογή Celery concurrency
- Χρήση gzip compression για API responses

** 🤝 Συνεισφορά**

- Fork το repository
- Δημιούργησε feature branch
- Κάνε commit τις αλλαγές
- Push στο branch
- Άνοιξε Pull Request

**Commit Guidelines**

text

feat: Προσθήκη νέου agent τύπου

fix: Διόρθωση σάρωσης Nmap

docs: Ενημέρωση README

test: Προσθήκη unit tests

refactor: Βελτιστοποίηση database queries

## 📄 Άδεια Χρήσης

Αυτό το project διανέμεται υπό την άδεια MIT. Δείτε το αρχείο [LICENSE](https://license/) για περισσότερες λεπτομέρειες.

** 📞 Υποστήριξη & Επαφή**

- **Issues**: [GitHub Issues](https://github.com/yourusername/security-system/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/security-system/discussions)
- **Email**: <belips@gmx.com>

### ⚠️ Σημείωση**: Αυτό το σύστημα προορίζεται για εκπαιδευτικούς και ερευνητικούς σκοπούς. Χρησιμοποιήστε το μόνο σε ελεγχόμενα περιβάλλοντα.
### Έγινε υπό την καθοδήγηση του Δρ. Αχιλλέα Δ. Καμέας Καθηγητή Συστημάτων Διάχυτου Υπολογισμού και την βωοήθεια του PhD Μανώλη Μαυροφίδη.
### Μία προσφορά για την Ασφάλεια των Βιομηχανικών Συστημάτων και των Συστημάτων Logistics
