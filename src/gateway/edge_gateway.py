import paho.mqtt.client as mqtt
from confluent_kafka import Producer, Consumer
import json
import time
import os
import re
import glob
import uuid
import threading
from queue import Queue, Empty
import requests
from datetime import datetime

# --- Payload validation limits (fix: gateway is a blind proxy, HIGH #4) ---
MAX_AGENT_ID_LEN = 128
AGENT_ID_PATTERN = re.compile(r'^[A-Za-z0-9_-]+$')
MAX_ANOMALIES = 100
MAX_ANOMALY_LEN = 256
MAX_METRICS_BYTES = 16384  # cap on the serialized size of the metrics blob

class EdgeGateway:
    def __init__(self):
        # Configuration
        self.MQTT_BROKER_HOST = os.getenv('MQTT_BROKER_HOST', 'localhost')
        self.MQTT_BROKER_PORT = int(os.getenv('MQTT_BROKER_PORT', 1883))
        # Broker now requires auth (allow_anonymous false, see
        # docker/mosquitto.conf) - the gateway needs its own credentials,
        # provisioned as the "edge_gateway" MQTT user (docker/mosquitto.acl).
        self.MQTT_USERNAME = os.getenv('MQTT_USERNAME')
        self.MQTT_PASSWORD = os.getenv('MQTT_PASSWORD')
        self.KAFKA_BOOTSTRAP_SERVERS = os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092')
        self.BACKEND_URL = os.getenv('BACKEND_URL', 'http://localhost:5000')
        
        # MQTT Topics
        self.MQTT_TOPIC_ALL_AGENTS = "security/agents/#"
        self.AGENT_TOPICS = {
            "robot": "security/agents/robot/#",
            "drone": "security/agents/drone/#", 
            "camera": "security/agents/camera/#",
            "iot": "security/agents/iot/#",
            "plc": "security/agents/plc/#"
        }
        
        # Kafka topic mapping
        self.KAFKA_TOPIC_MAP = {
            "robot_agent": "robot_events",
            "drone_agent": "drone_events",
            "camera_agent": "camera_events",
            "iot_agent": "iot_events",
            "plc_agent": "plc_events",
            "critical": "critical_alerts"
        }
        
        # System state
        self.sequence_counter = 0
        self.message_buffer = Queue(maxsize=1000)
        self.agent_status = {}

        # Topic used to surface conditions (e.g. buffer overflow) that
        # monitoring/the backend should see even though they aren't normal
        # telemetry (fix: unbounded flood was previously silent, MEDIUM #14)
        self.GATEWAY_ALERTS_TOPIC = "security/gateway/alerts"

        # Static topic -> expected agent_id map, derived from the agent
        # config files. Used to reject messages whose attacker-controlled
        # payload['agent_id'] doesn't match the agent that owns the topic
        # it was published on (fix: no sender authentication, CRITICAL #2).
        self.expected_agent_ids = self._load_expected_agent_ids()

        # Initialize components
        self.mqtt_client = self.setup_mqtt_client()
        self.kafka_producer = self.setup_kafka_producer()

        # Statistics
        self.stats = {
            'messages_received': 0,
            'messages_forwarded': 0,
            'errors': 0,
            'last_processed': None
        }
        # All mutation/reads of self.stats from the MQTT thread, the buffer
        # processing thread and the health-publishing thread must go
        # through this lock (fix: unsynchronized counters, MEDIUM #21).
        self.stats_lock = threading.Lock()

        print("🚀 Edge Gateway Initialized")
        print(f"   MQTT Broker: {self.MQTT_BROKER_HOST}:{self.MQTT_BROKER_PORT}")
        print(f"   Kafka: {self.KAFKA_BOOTSTRAP_SERVERS}")
        print(f"   Backend: {self.BACKEND_URL}")

    def setup_mqtt_client(self):
        """Configure and connect MQTT client"""
        client = mqtt.Client(client_id=f"edge-gateway-{uuid.uuid4().hex[:8]}")
        client.on_connect = self.on_mqtt_connect
        client.on_message = self.on_mqtt_message
        client.on_disconnect = self.on_mqtt_disconnect

        if self.MQTT_USERNAME:
            client.username_pw_set(self.MQTT_USERNAME, self.MQTT_PASSWORD)
        else:
            print("⚠️  No MQTT_USERNAME/MQTT_PASSWORD set for gateway; connection will "
                  "fail against a broker with allow_anonymous=false")

        # Set last will testament for gateway status
        client.will_set("security/gateway/status", payload="offline", retain=True)
        
        try:
            client.connect(self.MQTT_BROKER_HOST, self.MQTT_BROKER_PORT, 60)
            print("✅ Connected to MQTT Broker")
            return client
        except Exception as e:
            print(f"❌ Failed to connect to MQTT: {e}")
            return None

    def setup_kafka_producer(self):
        """Configure Kafka producer"""
        try:
            producer = Producer({
                'bootstrap.servers': self.KAFKA_BOOTSTRAP_SERVERS,
                'client.id': 'edge-gateway-producer',
                'acks': 'all',
                'retries': 3
            })
            print("✅ Kafka Producer configured")
            return producer
        except Exception as e:
            print(f"❌ Kafka Producer setup failed: {e}")
            return None

    def _load_expected_agent_ids(self):
        """Build a static agent_type -> {expected agent_ids} map, and a
        agent_type -> {'critical': [...], 'warning': [...]} alert-threshold
        map, both from the agent config files shipped in src/configs/.

        The agent_id map is a lightweight stand-in for real per-message
        sender authentication: it at least stops a client publishing on,
        say, security/agents/plc/# from claiming to be a different PLC (or
        a different agent type) than the ones actually provisioned. A full
        fix would have the gateway verify a per-agent HMAC signature on
        every message instead.

        The alert-threshold map wires up each agent config's
        reporting.alert_thresholds (previously defined but never read by
        anything, MEDIUM #20) into calculate_severity() below, so an
        agent-specific "this anomaly is always critical/warning" list
        actually affects routing/severity.
        """
        expected = {}
        alert_thresholds = {}
        try:
            configs_dir = os.path.join(os.path.dirname(__file__), '..', 'configs')
            for config_path in glob.glob(os.path.join(configs_dir, '*.json')):
                try:
                    with open(config_path, 'r') as f:
                        cfg = json.load(f)
                    agent_type = cfg.get('agent_type')
                    agent_id = cfg.get('agent_id')
                    if agent_type and agent_id:
                        expected.setdefault(agent_type, set()).add(agent_id)
                    thresholds = cfg.get('reporting', {}).get('alert_thresholds')
                    if agent_type and thresholds:
                        alert_thresholds[agent_type] = thresholds
                except (json.JSONDecodeError, OSError) as e:
                    print(f"⚠️  Could not load agent config {config_path}: {e}")
            if expected:
                print(f"🔒 Loaded expected agent_id map for sender cross-check: "
                      f"{ {k: sorted(v) for k, v in expected.items()} }")
            else:
                print("⚠️  No agent configs found; agent_id cross-check will be skipped "
                      "(sender identity is NOT verified)")
            if alert_thresholds:
                print(f"📋 Loaded per-agent alert_thresholds for severity routing: "
                      f"{list(alert_thresholds.keys())}")
        except Exception as e:
            print(f"⚠️  Failed to build expected agent_id map: {e}")
        self.alert_thresholds_by_type = alert_thresholds
        return expected

    def is_agent_id_expected(self, agent_type, agent_id):
        """Return True if agent_id is an allowed identity for agent_type,
        or if we have no config-derived expectation to check against
        (fail-open, since this is a best-effort mitigation, not full auth).
        """
        allowed = self.expected_agent_ids.get(agent_type)
        if not allowed:
            return True
        return agent_id in allowed

    def validate_payload(self, payload):
        """Schema/type/length validation for inbound agent payloads (fix:
        gateway was a blind proxy with no validation, HIGH #4). Returns
        (True, None) if the payload is acceptable, or (False, reason) if
        it should be rejected outright.
        """
        if not isinstance(payload, dict):
            return False, "payload is not a JSON object"

        agent_id = payload.get('agent_id')
        if not isinstance(agent_id, str) or not agent_id:
            return False, "agent_id missing or not a string"
        if len(agent_id) > MAX_AGENT_ID_LEN:
            return False, "agent_id exceeds max length"
        if not AGENT_ID_PATTERN.match(agent_id):
            return False, "agent_id contains disallowed characters"

        anomalies = payload.get('anomalies', [])
        if anomalies is not None:
            if not isinstance(anomalies, list):
                return False, "anomalies is not a list"
            if len(anomalies) > MAX_ANOMALIES:
                return False, "anomalies list exceeds max length"
            for anom in anomalies:
                if not isinstance(anom, str):
                    return False, "anomalies entry is not a string"
                if len(anom) > MAX_ANOMALY_LEN:
                    return False, "anomalies entry exceeds max length"

        metrics = payload.get('metrics', {})
        if metrics is not None:
            if not isinstance(metrics, dict):
                return False, "metrics is not an object"
            try:
                metrics_size = len(json.dumps(metrics))
            except (TypeError, ValueError):
                return False, "metrics is not JSON-serializable"
            if metrics_size > MAX_METRICS_BYTES:
                return False, "metrics payload exceeds max size"

        return True, None

    def on_mqtt_connect(self, client, userdata, flags, rc):
        """MQTT connection callback"""
        if rc == 0:
            print("✅ MQTT Connection established")
            # Subscribe to all agent topics
            for topic in self.AGENT_TOPICS.values():
                client.subscribe(topic)
                print(f"   📡 Subscribed to: {topic}")
            
            # Publish gateway online status
            client.publish("security/gateway/status", "online", retain=True)
        else:
            print(f"❌ MQTT Connection failed with code: {rc}")

    def on_mqtt_disconnect(self, client, userdata, rc):
        """MQTT disconnection callback"""
        print(f"⚠️  MQTT Disconnected (code: {rc})")
        if rc != 0:
            print("   Attempting to reconnect...")
            time.sleep(5)
            try:
                client.reconnect()
            except:
                print("   Reconnection failed")

    def on_mqtt_message(self, client, userdata, msg):
        """Handle incoming MQTT messages from agents"""
        try:
            payload = json.loads(msg.payload.decode('utf-8'))
            with self.stats_lock:
                self.stats['messages_received'] += 1

            # Add metadata to the message
            enriched_message = {
                'mqtt_topic': msg.topic,
                'received_at': datetime.utcnow().isoformat(),
                'gateway_id': 'edge-gateway-001',
                'raw_payload': payload
            }

            # Buffer the message for processing
            if not self.message_buffer.full():
                self.message_buffer.put(enriched_message)
                print(f"📨 Received message from {msg.topic} | Buffer: {self.message_buffer.qsize()}")
            else:
                print("⚠️  Message buffer full, dropping message")
                with self.stats_lock:
                    self.stats['errors'] += 1
                self.publish_buffer_overflow_event(msg.topic)

        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON in MQTT message: {e}")
            with self.stats_lock:
                self.stats['errors'] += 1
        except Exception as e:
            print(f"❌ Error processing MQTT message: {e}")
            with self.stats_lock:
                self.stats['errors'] += 1

    def publish_buffer_overflow_event(self, dropped_topic):
        """Make the buffer-full/drop condition visible to monitoring
        instead of only printing locally (fix: silent drop, MEDIUM #14).
        """
        try:
            if not self.mqtt_client:
                return
            event = {
                'event': 'buffer_overflow',
                'timestamp': datetime.utcnow().isoformat(),
                'gateway_id': 'edge-gateway-001',
                'buffer_maxsize': self.message_buffer.maxsize,
                'dropped_message_topic': dropped_topic
            }
            self.mqtt_client.publish(self.GATEWAY_ALERTS_TOPIC, json.dumps(event))
        except Exception as e:
            print(f"❌ Failed to publish buffer_overflow event: {e}")

    def preprocess_message(self, raw_message):
        """Normalize and enrich agent messages"""
        try:
            payload = raw_message['raw_payload']
            mqtt_topic = raw_message['mqtt_topic']

            # Schema/type/length validation (fix: blind proxy, HIGH #4).
            # Reject anything malformed before it's forwarded to Kafka/backend.
            is_valid, reason = self.validate_payload(payload)
            if not is_valid:
                print(f"❌ Dropping message from {mqtt_topic}: invalid payload ({reason})")
                with self.stats_lock:
                    self.stats['errors'] += 1
                return None

            # Extract agent type from topic
            agent_type = "unknown"
            for agent, topic_pattern in self.AGENT_TOPICS.items():
                if topic_pattern.replace('#', '') in mqtt_topic:
                    agent_type = f"{agent}_agent"
                    break

            agent_id = payload.get('agent_id', 'unknown')

            # Sender cross-check (fix: no sender authentication, CRITICAL #2).
            # The topic and the payload's self-reported agent_id are both
            # attacker-controlled once MQTT is reachable; at minimum verify
            # they're consistent with the configured agent for that topic.
            if not self.is_agent_id_expected(agent_type, agent_id):
                print(f"❌ Dropping message from {mqtt_topic}: agent_id '{agent_id}' "
                      f"is not a recognized {agent_type} identity (possible identity spoofing)")
                with self.stats_lock:
                    self.stats['errors'] += 1
                return None

            # Track last-seen status per agent (fix: agent_status dict was
            # never populated, HIGH #6) so gateway health accurately
            # reflects the number of active agents.
            severity = self.calculate_severity(payload, agent_type)
            self.agent_status[agent_id] = {
                'agent_type': agent_type,
                'last_seen_utc': raw_message['received_at'],
                'last_severity': severity,
                'mqtt_topic': mqtt_topic
            }

            # Create normalized message
            normalized_message = {
                'message_id': str(uuid.uuid4()),
                'agent_id': agent_id,
                'agent_type': agent_type,
                'gateway_id': raw_message['gateway_id'],
                'received_timestamp_utc': raw_message['received_at'],
                'sequence_number': self.get_next_sequence(),
                'telemetry_type': 'anomaly' if payload.get('anomalies') else 'telemetry',
                'severity': severity,
                'kafka_topic': self.KAFKA_TOPIC_MAP.get(agent_type, 'unknown_events'),
                'risk_scores': {
                    'agent_risk_score': payload.get('security_score', 100),
                    'criticality': self.get_criticality(payload.get('security_score', 100))
                },
                'raw_payload': payload,
                'normalized_payload': {
                    'timestamp_utc': payload.get('timestamp', raw_message['received_at']),
                    'metrics': payload.get('metrics', {}),
                    'status_flags': {
                        'has_anomalies': len(payload.get('anomalies', [])) > 0,
                        'low_security_score': payload.get('security_score', 100) < 50
                    },
                    'anomalies': payload.get('anomalies', [])
                },
                'forwarding_info': {
                    'retry_count': 0,
                    'last_attempt': None,
                    'status': 'pending'
                }
            }
            
            return normalized_message
            
        except Exception as e:
            print(f"❌ Error preprocessing message: {e}")
            with self.stats_lock:
                self.stats['errors'] += 1
            return None

    def calculate_severity(self, payload, agent_type=None):
        """Calculate message severity based on content, honoring the
        per-agent-type reporting.alert_thresholds config (fix: dead
        alert_thresholds config, MEDIUM #20) when the agent_type is known.
        """
        score = payload.get('security_score', 100)
        anomalies = payload.get('anomalies', [])
        thresholds = self.alert_thresholds_by_type.get(agent_type, {})

        if any(a in thresholds.get('critical', []) for a in anomalies):
            return 'critical'

        if score < 30 or any('critical' in str(anom).lower() for anom in anomalies):
            return 'critical'

        if (any(a in thresholds.get('warning', []) for a in anomalies)
                or score < 60 or len(anomalies) > 0):
            return 'warning'

        return 'info'

    def get_criticality(self, score):
        """Get criticality level from score"""
        if score >= 80:
            return 'low'
        elif score >= 50:
            return 'moderate'
        else:
            return 'high'

    def get_next_sequence(self):
        """Get next sequence number"""
        self.sequence_counter += 1
        return self.sequence_counter

    def kafka_delivery_report(self, err, msg):
        """Kafka message delivery callback"""
        if err is not None:
            print(f'❌ Message delivery failed: {err}')
            with self.stats_lock:
                self.stats['errors'] += 1
        else:
            with self.stats_lock:
                self.stats['messages_forwarded'] += 1
            print(f'✅ Message delivered to {msg.topic()} [{msg.partition()}]')

    def _produce_to_kafka_topic(self, topic, key, message_value):
        """Low-level produce helper shared by normal and critical-alert forwarding."""
        self.kafka_producer.produce(
            topic,
            key=key,
            value=message_value,
            callback=self.kafka_delivery_report
        )

    def forward_to_kafka(self, normalized_message):
        """Forward normalized message to Kafka. Critical-severity messages
        are ALSO forwarded to the dedicated critical_alerts topic (fix:
        the "critical" KAFKA_TOPIC_MAP entry was dead code because
        agent_type is never "critical", HIGH #7), in addition to their
        normal per-agent-type topic.
        """
        try:
            topic = normalized_message['kafka_topic']
            message_key = normalized_message['agent_id']
            message_value = json.dumps(normalized_message).encode('utf-8')

            self._produce_to_kafka_topic(topic, message_key, message_value)

            # Also route critical-severity messages to critical_alerts.
            if normalized_message.get('severity') == 'critical':
                critical_topic = self.KAFKA_TOPIC_MAP.get('critical')
                if critical_topic and critical_topic != topic:
                    self._produce_to_kafka_topic(critical_topic, message_key, message_value)
                    print(f"🚨 Also forwarded to Kafka [{critical_topic}] (critical): "
                          f"{normalized_message['agent_id']}")

            # Trigger delivery reports
            self.kafka_producer.poll(0)

            print(f"📤 Forwarded to Kafka [{topic}]: {normalized_message['agent_id']}")

        except Exception as e:
            print(f"❌ Error forwarding to Kafka: {e}")
            with self.stats_lock:
                self.stats['errors'] += 1

    def send_to_backend(self, normalized_message):
        """Send important messages directly to backend API"""
        try:
            # Only send critical/warning messages to reduce load
            if normalized_message['severity'] in ['critical', 'warning']:
                backend_payload = {
                    'agent_id': normalized_message['agent_id'],
                    'timestamp': normalized_message['received_timestamp_utc'],
                    'security_score': normalized_message['risk_scores']['agent_risk_score'],
                    'anomalies': normalized_message['normalized_payload']['anomalies'],
                    'metrics': normalized_message['normalized_payload']['metrics']
                }
                
                response = requests.post(
                    f"{self.BACKEND_URL}/api/telemetry",
                    json=backend_payload,
                    timeout=5
                )
                
                if response.status_code == 200:
                    print(f"📨 Sent to backend: {normalized_message['agent_id']}")
                else:
                    print(f"⚠️  Backend response: {response.status_code}")
                    
        except requests.exceptions.RequestException as e:
            print(f"❌ Backend communication error: {e}")

    def process_message_buffer(self):
        """Process messages from buffer in separate thread"""
        while True:
            try:
                # Wait for message with timeout
                raw_message = self.message_buffer.get(timeout=1)
                
                # Preprocess and normalize
                normalized_message = self.preprocess_message(raw_message)
                
                if normalized_message:
                    # Forward to Kafka
                    self.forward_to_kafka(normalized_message)

                    # Send to backend if important
                    self.send_to_backend(normalized_message)

                    # Update stats
                    with self.stats_lock:
                        self.stats['last_processed'] = datetime.utcnow().isoformat()

                self.message_buffer.task_done()

            except Empty:
                # No messages in buffer, continue
                continue
            except Exception as e:
                print(f"❌ Error in buffer processing: {e}")
                with self.stats_lock:
                    self.stats['errors'] += 1

    def publish_gateway_health(self):
        """Publish gateway health status periodically"""
        while True:
            try:
                with self.stats_lock:
                    stats_snapshot = dict(self.stats)

                health_status = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'status': 'healthy',
                    'stats': stats_snapshot,
                    'buffer_size': self.message_buffer.qsize(),
                    'agent_count': len(self.agent_status)
                }

                self.mqtt_client.publish(
                    "security/gateway/health",
                    json.dumps(health_status),
                    retain=True
                )

                print(f"❤️  Gateway Health | Buffer: {self.message_buffer.qsize()} | "
                      f"Received: {stats_snapshot['messages_received']} | "
                      f"Forwarded: {stats_snapshot['messages_forwarded']}")

            except Exception as e:
                print(f"❌ Health publish error: {e}")

            time.sleep(30)  # Every 30 seconds

    def run(self):
        """Main gateway operation"""
        if not self.mqtt_client or not self.kafka_producer:
            print("❌ Gateway components not properly initialized")
            return
        
        print("🚀 Starting Edge Gateway...")
        
        # Start buffer processing thread
        buffer_thread = threading.Thread(target=self.process_message_buffer, daemon=True)
        buffer_thread.start()
        
        # Start health monitoring thread
        health_thread = threading.Thread(target=self.publish_gateway_health, daemon=True)
        health_thread.start()
        
        # Start MQTT loop
        try:
            self.mqtt_client.loop_forever()
        except KeyboardInterrupt:
            print("\n🛑 Shutting down Edge Gateway...")
        finally:
            # Cleanup
            self.mqtt_client.disconnect()
            self.kafka_producer.flush(10)
            print("✅ Gateway shutdown complete")

if __name__ == "__main__":
    gateway = EdgeGateway()
    gateway.run()
