
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

## UML Διαγράμματα
### Component Diagram του Συστήματος

```mermaid
graph TB
    %% External Systems
    IoT_Agents[IoT Agents<br/>Cameras, Drones, Robots, Sensors, PLCs]
    Frontend[Frontend Application<br/>Monitoring Dashboard]
    Security_Scanners[Security Scanners<br/>nmap, nuclei, custom]
    Admin_Tools[Admin Tools<br/>CLI, Management Console]
    
    %% Backend Components
    API_GW[API Gateway / Load Balancer]
    Flask_App[Flask Application Container]
    Web_Server[Web Server<br/>Gunicorn]
    Business_Logic[Business Logic<br/>Services]
    Auth_Module[Authentication Module<br/>JWT/API Keys]
    API_Routes[API Routes<br/>REST Endpoints]
    
    %% Message Brokers
    MQTT_Broker[MQTT Broker<br/>Mosquitto]
    Redis_Broker[Redis Broker<br/>Cache/Queue]
    Kafka_Broker[Kafka Broker<br/>Event Streaming]
    Celery_Queue[Celery Message Queue]
    
    %% Data Storage
    PostgreSQL[PostgreSQL Database<br/>Primary Storage]
    Redis_Cache[Redis Cache<br/>Sessions/Temp Data]
    File_System[File System<br/>Logs/Reports]
    Docker_Images[Docker Images<br/>Security Scanners]
    
    %% Connections
    IoT_Agents --> MQTT_Broker
    Frontend --> API_GW
    Security_Scanners --> Celery_Queue
    Admin_Tools --> API_GW
    
    API_GW --> Flask_App
    
    Flask_App --> Web_Server
    Web_Server --> Business_Logic
    Business_Logic --> Auth_Module
    Business_Logic --> API_Routes
    
    Business_Logic --> MQTT_Broker
    Business_Logic --> Redis_Broker
    Business_Logic --> Kafka_Broker
    Business_Logic --> Celery_Queue
    
    Business_Logic --> PostgreSQL
    Business_Logic --> Redis_Cache
    Business_Logic --> File_System
    Business_Logic --> Docker_Images
    
    %% Internal connections
    MQTT_Broker -.-> Redis_Broker
    Celery_Queue -.-> PostgreSQL
    Kafka_Broker -.-> File_System
    
    %% Styling
    classDef external fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef backend fill:#f3e5f5,stroke:#4a148c,stroke-width:2px
    classDef broker fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    classDef storage fill:#fff3e0,stroke:#e65100,stroke-width:2px
    
    class IoT_Agents,Frontend,Security_Scanners,Admin_Tools external
    class API_GW,Flask_App,Web_Server,Business_Logic,Auth_Module,API_Routes backend
    class MQTT_Broker,Redis_Broker,Kafka_Broker,Celery_Queue broker
    class PostgreSQL,Redis_Cache,File_System,Docker_Images storage
'''

### Class Diagram των Κύριων Κλάσεων

```mermaid
classDiagram
    %% Main Application Class
    class FlaskApplication {
        -app: Flask
        -db: SQLAlchemy
        -celery_app: Celery
        +init_database()
        +create_tables()
        +register_blueprints()
        +configure_logging()
        +run_server()
    }
    
    %% Database Models
    class User {
        +id: Integer
        +username: String
        +email: String
        +password_hash: String
        +role: String
        +api_key: String
        +is_active: Boolean
        +created_at: DateTime
        +last_login: DateTime
        +set_password(password)
        +check_password(password)
        +generate_api_key()
        +authenticate(username, password)
    }
    
    class Agent {
        +id: Integer
        +agent_id: String
        +agent_type: String
        +location: String
        +status: String
        +api_key: String
        +created_at: DateTime
        +last_seen: DateTime
        +get_by_api_key(api_key)
        +update_last_seen()
    }
    
    class Telemetry {
        +id: Integer
        +agent_id: ForeignKey
        +timestamp: DateTime
        +security_score: Integer
        +metrics: Text
        +anomalies: Text
        +get_metrics()
        +get_anomalies()
    }
    
    class Alert {
        +id: Integer
        +agent_id: ForeignKey
        +timestamp: DateTime
        +severity: String
        +message: Text
        +resolved: Boolean
        +resolved_at: DateTime
        +to_dict()
    }
    
    class SecurityScan {
        +id: Integer
        +tool: String
        +target: String
        +results: JSON
        +success: Boolean
        +created_at: DateTime
        +vulnerabilities_found: Integer
    }
    
    %% Service Classes
    class AuthenticationService {
        -secret_key: String
        -token_expiry: Integer
        +verify_api_key(api_key)
        +generate_jwt_token(user)
        +validate_jwt_token(token)
        +get_current_user()
    }
    
    class TelemetryService {
        -buffer_size: Integer
        -processing_interval: Integer
        +receive_telemetry(data)
        +process_telemetry_batch()
        +calculate_security_score(metrics)
        +detect_anomalies(data)
        +store_telemetry(agent_id, data)
    }
    
    class AlertService {
        -alert_rules: List
        -notification_channels: List
        +evaluate_telemetry(telemetry)
        +create_alert(agent_id, severity, message)
        +resolve_alert(alert_id)
        +send_notification(alert)
        +get_active_alerts()
    }
    
    class SecurityScannerService {
        -docker_client: DockerClient
        -scan_tools: Dict
        +run_nmap_scan(target, options)
        +run_nuclei_scan(target, template_type)
        +save_scan_results(results)
        +analyze_results(results)
        +create_vulnerability_report()
    }
    
    class MessageBrokerService {
        -mqtt_client: MQTTClient
        -redis_client: Redis
        -kafka_producer: Producer
        +publish_mqtt(topic, message)
        +subscribe_mqtt(topic, callback)
        +publish_redis(channel, message)
        +publish_kafka(topic, message)
        +consume_kafka(topic, callback)
    }
    
    %% Controller Classes
    class APIController {
        +handle_telemetry_endpoint()
        +handle_agents_endpoint()
        +handle_alerts_endpoint()
        +handle_auth_endpoint()
        +handle_scan_endpoint()
        +validate_request(request)
        +format_response(data)
        +handle_error(error)
    }
    
    class AgentController {
        +register_agent(agent_data)
        +update_agent_status(agent_id, status)
        +get_agent_telemetry(agent_id, timeframe)
        +get_agent_alerts(agent_id)
        +revoke_agent_api_key(agent_id)
    }
    
    %% Task Classes (Celery)
    class CeleryTaskBase {
        +task_id: String
        +status: String
        +result: Any
        +execute()
        +on_success(result)
        +on_failure(error)
        +retry(max_retries)
    }
    
    class NmapScanTask {
        -target: String
        -options: String
        +run()
        +parse_results(output)
        +save_to_database(results)
    }
    
    class NucleiScanTask {
        -target: String
        -template_type: String
        +run()
        +parse_json_results(output)
        +categorize_vulnerabilities(results)
    }
    
    class TelemetryProcessingTask {
        -batch_size: Integer
        +process_batch(telemetry_batch)
        +aggregate_metrics(telemetry_list)
        +detect_correlated_anomalies(batch)
    }
    
    %% Relationships
    FlaskApplication --> AuthenticationService
    FlaskApplication --> TelemetryService
    FlaskApplication --> AlertService
    FlaskApplication --> SecurityScannerService
    
    User "1" -- "*" Agent : registers
    Agent "1" -- "*" Telemetry : generates
    Agent "1" -- "*" Alert : triggers
    TelemetryService --> Telemetry : creates
    AlertService --> Alert : creates
    
    SecurityScannerService --> SecurityScan : creates
    SecurityScannerService --> NmapScanTask : executes
    SecurityScannerService --> NucleiScanTask : executes
    
    APIController --> AuthenticationService : uses
    APIController --> TelemetryService : uses
    APIController --> AlertService : uses
    
    MessageBrokerService --> TelemetryService : notifies
    MessageBrokerService --> AlertService : notifies
    
    CeleryTaskBase <|-- NmapScanTask
    CeleryTaskBase <|-- NucleiScanTask
    CeleryTaskBase <|-- TelemetryProcessingTask
    
    %% Additional utility classes
    class ConfigurationManager {
        -config_file: String
        -environment: String
        +get_database_url()
        +get_redis_url()
        +get_secret_key()
        +get_mqtt_broker()
        +load_environment()
    }
    
    class LoggingService {
        -log_file: String
        -log_level: String
        +log_info(message)
        +log_error(message, exception)
        +log_debug(message)
        +log_security_event(event)
    }
    
    ConfigurationManager --> FlaskApplication : configures
    LoggingService --> FlaskApplication : logs
'''


### Activity Diagram για Telemetry Processing

```mermaid
flowchart TD
    A[Start System] --> B[Initialize Components]
    B --> C{Database Available?}
    C -->|Yes| D[Create Tables]
    C -->|No| E[Wait & Retry]
    E --> C
    D --> F[Load Configuration]
    F --> G[Start Flask Server]
    G --> H[Listen for Requests]
    
    subgraph HTTP_Request_Handling
        H --> I{Request Type?}
        I -->|Telemetry| J[Receive Telemetry Data]
        I -->|API Call| K[Authenticate Request]
        I -->|Security Scan| L[Queue Scan Task]
        
        J --> M[Validate API Key]
        M --> N{Valid?}
        N -->|Yes| O[Process Telemetry]
        N -->|No| P[Return 401 Unauthorized]
        
        O --> Q[Store in Database]
        Q --> R[Analyze for Anomalies]
        R --> S{Anomaly Detected?}
        S -->|Yes| T[Create Alert]
        S -->|No| U[Update Agent Status]
        T --> U
        
        K --> V[Check Authentication]
        V --> W{Authenticated?}
        W -->|Yes| X[Process API Request]
        W -->|No| Y[Return Error]
        X --> Z[Return Response]
        
        L --> AA[Validate Scan Request]
        AA --> AB[Create Celery Task]
        AB --> AC[Execute in Container]
        AC --> AD[Parse Results]
        AD --> AE[Store Results]
        AE --> AF[Create Alerts if Vulnerabilities]
    end
    
    subgraph Background_Processing
        AG[Start Celery Worker] --> AH[Monitor Task Queue]
        AH --> AI{Task Available?}
        AI -->|Yes| AJ[Execute Task]
        AI -->|No| AH
        AJ --> AK[Update Task Status]
        AK --> AL[Store Results]
        AL --> AH
        
        AM[Start MQTT Listener] --> AN[Subscribe to Topics]
        AN --> AO{Message Received?}
        AO -->|Yes| AP[Process MQTT Message]
        AO -->|No| AN
        AP --> AQ[Convert to Telemetry]
        AQ --> AR[Forward to HTTP endpoint]
    end
    
    subgraph Monitoring_Activities
        AS[Health Check Scheduler] --> AT[Check System Health]
        AT --> AU{All Systems Healthy?}
        AU -->|Yes| AV[Log Status]
        AU -->|No| AW[Send Alert]
        AV --> AS
        AW --> AS
        
        AX[Performance Monitor] --> AY[Collect Metrics]
        AY --> AZ[Analyze Trends]
        AZ --> BA{Performance Degradation?}
        BA -->|Yes| BB[Trigger Auto-scaling]
        BA -->|No| AX
        BB --> AX
    end
    
    U --> H
    P --> H
    Y --> H
    Z --> H
    AF --> H
    AR --> J
    
    %% Styling
    classDef startEnd fill:#ffcccc,stroke:#ff0000,stroke-width:2px
    classDef decision fill:#ffffcc,stroke:#ffcc00,stroke-width:2px
    classDef process fill:#ccffcc,stroke:#00cc00,stroke-width:2px
    classDef subgraph fill:#e6f3ff,stroke:#0066cc,stroke-width:2px
    
    class A startEnd
    class C,I,N,S,W,AI,AO,AU,BA decision
    class B,D,E,F,G,J,K,L,M,O,P,Q,R,T,U,V,X,Y,Z,AA,AB,AC,AD,AE,AF,AG,AH,AJ,AK,AL,AM,AN,AP,AQ,AR,AS,AT,AV,AW,AX,AY,AZ,BB process
    class HTTP_Request_Handling,Background_Processing,Monitoring_Activities subgraph
'''


### Use Case Diagram των Χρηστών

```mermaid
graph TB
    %% Actors
    IoT_Device[IoT Device<br/>Camera, Drone, Robot, Sensor, PLC]
    Security_Analyst[Security Analyst<br/>/ Operator]
    System_Administrator[System Administrator]
    Monitoring_System[Monitoring System<br/>Frontend / External]
    Security_Scanner[Security Scanner<br/>Automated Tool]
    
    %% Use Cases - Agent Management
    UC1[UC-01: Register Device<br/>Register new IoT device in system]
    UC2[UC-02: Send Telemetry Data<br/>Send security metrics to backend]
    UC3[UC-03: Update Device Status<br/>Report operational status]
    UC4[UC-04: Receive Configuration<br/>Get updated security policies]
    
    %% Use Cases - Security Monitoring
    UC5[UC-05: View Security Dashboard<br/>Monitor overall system security]
    UC6[UC-06: Analyze Anomalies<br/>Investigate security events]
    UC7[UC-07: Acknowledge Alerts<br/>Confirm and process security alerts]
    UC8[UC-08: Generate Security Reports<br/>Create compliance reports]
    
    %% Use Cases - System Administration
    UC9[UC-09: Manage Users<br/>Create, update, delete system users]
    UC10[UC-10: Configure System<br/>Set system parameters and policies]
    UC11[UC-11: Backup/Restore System<br/>Manage system data backup]
    UC12[UC-12: Monitor System Health<br/>Check system performance]
    
    %% Use Cases - Security Scanning
    UC13[UC-13: Initiate Security Scan<br/>Start vulnerability assessment]
    UC14[UC-14: Schedule Automated Scans<br/>Configure recurring scans]
    UC15[UC-15: Review Scan Results<br/>Analyze vulnerability findings]
    UC16[UC-16: Remediate Vulnerabilities<br/>Process and fix findings]
    
    %% Use Cases - Data Management
    UC17[UC-17: Query Historical Data<br/>Access historical telemetry]
    UC18[UC-18: Export Data<br/>Export data for external analysis]
    UC19[UC-19: Purge Old Data<br/>Remove outdated records]
    UC20[UC-20: Audit Log Access<br/>Review system audit logs]
    
    %% Extend Relationships
    UC21[UC-21: Real-time Alerting<br/>Immediate notification on critical events]
    UC22[UC-22: Predictive Analysis<br/>Predict potential security threats]
    
    %% Include Relationships
    UC23[UC-23: Authenticate User<br/>Verify user credentials]
    UC24[UC-24: Authorize Action<br/>Check user permissions]
    UC25[UC-25: Log Activity<br/>Record system activities]
    UC26[UC-26: Validate Input<br/>Validate all user inputs]
    
    %% Actor to Use Case Connections
    IoT_Device --> UC1
    IoT_Device --> UC2
    IoT_Device --> UC3
    IoT_Device --> UC4
    
    Security_Analyst --> UC5
    Security_Analyst --> UC6
    Security_Analyst --> UC7
    Security_Analyst --> UC8
    Security_Analyst --> UC13
    Security_Analyst --> UC15
    Security_Analyst --> UC16
    Security_Analyst --> UC17
    Security_Analyst --> UC18
    
    System_Administrator --> UC9
    System_Administrator --> UC10
    System_Administrator --> UC11
    System_Administrator --> UC12
    System_Administrator --> UC19
    System_Administrator --> UC20
    
    Monitoring_System --> UC5
    Monitoring_System --> UC21
    
    Security_Scanner --> UC13
    Security_Scanner --> UC14
    
    %% Extend Relationships
    UC5 -.->|extends| UC21
    UC6 -.->|extends| UC22
    
    %% Include Relationships
    UC1 -.->|includes| UC23
    UC9 -.->|includes| UC23
    UC13 -.->|includes| UC23
    
    UC1 -.->|includes| UC24
    UC9 -.->|includes| UC24
    UC13 -.->|includes| UC24
    
    UC2 -.->|includes| UC25
    UC7 -.->|includes| UC25
    UC16 -.->|includes| UC25
    
    UC1 -.->|includes| UC26
    UC2 -.->|includes| UC26
    UC9 -.->|includes| UC26
    
    %% Styling
    classDef actor fill:#d4e6f1,stroke:#3498db,stroke-width:2px
    classDef usecase fill:#fef9e7,stroke:#f39c12,stroke-width:2px
    classDef extend fill:#e8f8f5,stroke:#1abc9c,stroke-width:2px
    classDef include fill:#fdedec,stroke:#e74c3c,stroke-width:2px
    
    class IoT_Device,Security_Analyst,System_Administrator,Monitoring_System,Security_Scanner actor
    class UC1,UC2,UC3,UC4,UC5,UC6,UC7,UC8,UC9,UC10,UC11,UC12,UC13,UC14,UC15,UC16,UC17,UC18,UC19,UC20 usecase
    class UC21,UC22 extend
    class UC23,UC24,UC25,UC26 include
'''


### Sequence Diagram για Telemetry Collection

```mermaid
sequenceDiagram
    title Sequence Diagram: Telemetry Collection from IoT Device
    
    participant Device as IoT Device<br/>(Camera/Robot/Sensor)
    participant MQTT as MQTT Broker<br/>(Mosquitto)
    participant Gateway as Edge Gateway
    participant API as Backend API<br/>(Flask)
    participant Auth as Auth Service
    participant DB as Database<br/>(PostgreSQL)
    participant Redis as Cache<br/>(Redis)
    participant Celery as Celery Worker
    participant Alert as Alert Service
    
    Note over Device,Alert: Phase 1: Data Collection & Transmission
    Device->>Device: Collect sensor data &<br/>calculate security metrics
    Device->>MQTT: Publish telemetry data<br/>(QoS 1, topic: security/agents/{type}/{id}/telemetry)
    MQTT->>Gateway: Forward message to gateway
    
    Note over Device,Alert: Phase 2: Gateway Processing
    Gateway->>Gateway: Parse & enrich message<br/>(add timestamp, gateway ID)
    Gateway->>Gateway: Normalize data format<br/>(standard JSON schema)
    Gateway->>API: HTTP POST /api/telemetry<br/>(with enriched data)
    
    Note over Device,Alert: Phase 3: API Authentication & Validation
    API->>Auth: Validate API Key<br/>(X-API-Key header)
    Auth-->>API: Authentication result
    alt Invalid API Key
        API-->>Gateway: Return 401 Unauthorized
        Gateway-->>Device: (via MQTT) Error notification
    else Valid API Key
        API->>API: Validate telemetry data<br/>(schema, completeness)
        API->>Redis: Cache recent telemetry<br/>(for fast access)
        
        Note over Device,Alert: Phase 4: Data Storage
        API->>DB: Store telemetry record<br/>(agents, timestamp, metrics, score)
        DB-->>API: Storage confirmation
        
        Note over Device,Alert: Phase 5: Real-time Analysis
        API->>Celery: Queue telemetry analysis task<br/>(async processing)
        Celery->>Celery: Analyze for anomalies<br/>(statistical analysis, threshold checks)
        Celery->>Celery: Calculate security score<br/>(weighted metrics)
        
        alt Anomaly Detected
            Celery->>Alert: Create security alert<br/>(severity, message, agent_id)
            Alert->>DB: Store alert record
            Alert->>Redis: Publish alert notification<br/>(pub/sub channel)
            Alert-->>API: Alert creation confirmation
        end
        
        Note over Device,Alert: Phase 6: Response & Update
        API->>DB: Update agent last_seen timestamp
        API->>Redis: Update agent status cache
        API-->>Gateway: HTTP 200 OK<br/>(with processing summary)
        Gateway-->>Device: (optional) Acknowledgment<br/>via MQTT retained message
    end
    
    Note over Device,Alert: Phase 7: Background Processing
    Celery->>Celery: Aggregate telemetry data<br/>(hourly/daily aggregates)
    Celery->>DB: Store aggregates for reporting
    Celery->>Celery: Cleanup old cached data
'''

### Sequence Diagram για Security Scanning Sequence

```mermaid
sequenceDiagram
    title Sequence Diagram: Security Vulnerability Scanning
    
    participant Analyst as Security Analyst
    participant Frontend as Frontend UI
    participant API as Backend API
    participant Auth as Auth Service
    participant Celery as Celery Task Queue
    participant Docker as Docker Engine
    participant Scanner as Security Scanner<br/>(nmap/nuclei container)
    participant DB as Database
    participant Alert as Alert Service
    
    Note over Analyst,Alert: Phase 1: Scan Request Initiation
    Analyst->>Frontend: Request security scan<br/>(target, scan type, options)
    Frontend->>API: POST /api/security-scanner/scan<br/>(with scan parameters)
    
    Note over Analyst,Alert: Phase 2: Authentication & Validation
    API->>Auth: Validate user session/API key
    Auth-->>API: Authentication result
    alt Not Authenticated
        API-->>Frontend: Return 401 Unauthorized
    else Authenticated
        API->>API: Validate scan parameters<br/>(target format, scan type)
        API->>Celery: Create scan task<br/>(task_id, parameters)
        Celery-->>API: Task queued confirmation
        API-->>Frontend: HTTP 202 Accepted<br/>(with task_id for tracking)
        
        Note over Analyst,Alert: Phase 3: Task Execution
        Celery->>Docker: Pull scanner image<br/>(if not available)
        Docker-->>Celery: Image ready
        Celery->>Docker: Run scanner container<br/>(with target parameters)
        Docker->>Scanner: Execute scan command<br/>(nmap -sV {target})
        
        Note over Analyst,Alert: Phase 4: Scan Execution
        Scanner->>Scanner: Perform security scan<br/>(port scanning, service detection)
        Scanner->>Scanner: Analyze results<br/>(vulnerability detection)
        Scanner-->>Docker: Scan results (stdout/stderr)
        Docker-->>Celery: Container execution complete
        
        Note over Analyst,Alert: Phase 5: Results Processing
        Celery->>Celery: Parse scan results<br/>(JSON/XML parsing)
        Celery->>Celery: Analyze vulnerabilities<br/>(CVSS scoring, classification)
        Celery->>DB: Store scan results<br/>(security_scans table)
        
        alt Vulnerabilities Found
            Celery->>Alert: Create vulnerability alerts<br/>(per vulnerability)
            Alert->>DB: Store alerts
            Alert->>Alert: Send notifications<br/>(email, dashboard)
        end
        
        Note over Analyst,Alert: Phase 6: Status Updates
        loop Progress Updates
            Celery->>Celery: Update task progress<br/>(percentage, status)
            Celery->>DB: Update task status
        end
        
        Celery-->>Celery: Task completion<br/>(SUCCESS/FAILURE)
        
        Note over Analyst,Alert: Phase 7: Results Retrieval
        Analyst->>Frontend: Check scan status<br/>(using task_id)
        Frontend->>API: GET /api/security-scanner/status/{task_id}
        API->>DB: Query task results
        DB-->>API: Scan results
        API-->>Frontend: Results with status
        
        Note over Analyst,Alert: Phase 8: Results Presentation
        Frontend->>Frontend: Format results for display<br/>(vulnerability list, severity chart)
        Frontend-->>Analyst: Display scan report<br/>(with remediation recommendations)
    end
'''


### Sequence Diagram για System Startup Sequence


```mermaid
sequenceDiagram
    title Sequence Diagram: System Startup & Initialization
    
    participant Docker as Docker Compose
    participant Postgres as PostgreSQL
    participant Redis as Redis
    participant MQTT as MQTT Broker
    participant Flask as Flask Application
    participant CeleryW as Celery Worker
    participant CeleryB as Celery Beat
    participant Flower as Flower Monitor
    participant Init as Initialization Script
    
    Note over Docker,Flower: Phase 1: Container Startup
    Docker->>Postgres: Start PostgreSQL container<br/>(port 5432)
    Docker->>Redis: Start Redis container<br/>(port 6379)
    Docker->>MQTT: Start Mosquitto container<br/>(port 1883)
    
    Note over Docker,Flower: Phase 2: Database Initialization
    Postgres->>Postgres: Initialize database<br/>(security_db)
    Postgres->>Postgres: Execute schema scripts<br/>(unified_schema.sql)
    Postgres->>Postgres: Create tables & indexes
    
    Note over Docker,Flower: Phase 3: Application Startup
    Docker->>Flask: Start Flask application<br/>(port 5000)
    Flask->>Postgres: Test database connection
    Postgres-->>Flask: Connection successful
    Flask->>Redis: Test Redis connection
    Redis-->>Flask: Connection successful
    Flask->>Flask: Initialize SQLAlchemy<br/>(create_all tables)
    Flask->>Flask: Create default admin user<br/>(if not exists)
    Flask->>Flask: Register API endpoints<br/>(routes, blueprints)
    
    Note over Docker,Flower: Phase 4: Worker Startup
    Docker->>CeleryW: Start Celery Worker
    CeleryW->>Redis: Connect to broker
    Redis-->>CeleryW: Connection established
    CeleryW->>CeleryW: Register task handlers<br/>(nmap_scan_task, nuclei_scan_task, etc.)
    
    Docker->>CeleryB: Start Celery Beat
    CeleryB->>Redis: Connect to broker
    CeleryB->>CeleryB: Schedule periodic tasks<br/>(daily scans, cleanup, etc.)
    
    Note over Docker,Flower: Phase 5: Monitoring Startup
    Docker->>Flower: Start Flower monitor<br/>(port 5555)
    Flower->>Redis: Connect to broker
    Flower->>Flower: Initialize monitoring<br/>(task tracking, worker status)
    
    Note over Docker,Flower: Phase 6: Health Checks
    loop Until Healthy
        Flask->>Flask: Health check endpoint<br/>(/health)
        Flask->>Postgres: Database health check
        Flask->>Redis: Redis health check
        Flask-->>Docker: Health status reporting
    end
    
    Note over Docker,Flower: Phase 7: Demo Data (Optional)
    Docker->>Init: Execute initialization script
    Init->>Postgres: Create demo data<br/>(users, agents, telemetry)
    Init->>Postgres: Generate API keys<br/>(for testing)
    Init-->>Docker: Initialization complete
    
    Note over Docker,Flower: Phase 8: Ready State
    Flask-->>Docker: Application ready<br/>(port 5000/15000)
    CeleryW-->>Docker: Worker ready
    CeleryB-->>Docker: Beat scheduler ready
    Flower-->>Docker: Monitoring ready<br/>(port 5555)
    
    Note right of Docker: System fully operational
'''


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
### Έγινε υπό την καθοδήγηση του Δρ. Αχιλλέα Δ. Καμέας Καθηγητή Συστημάτων Διάχυτου Υπολογισμού και την βοήθεια του PhD Μανώλη Μαυροφίδη.
### Μία προσφορά για την Ασφάλεια των Βιομηχανικών Συστημάτων και των Συστημάτων Logistics
