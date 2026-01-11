import paho.mqtt.client as mqtt
from confluent_kafka import Producer, Consumer
import json
import time
import os
import uuid
import threading
from queue import Queue, Empty
import requests
from datetime import datetime

class EdgeGateway:
    def __init__(self):
        # Configuration
        self.MQTT_BROKER_HOST = os.getenv('MQTT_BROKER_HOST', 'localhost')
        self.MQTT_BROKER_PORT = int(os.getenv('MQTT_BROKER_PORT', 1883))
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
                self.stats['errors'] += 1
                
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON in MQTT message: {e}")
            self.stats['errors'] += 1
        except Exception as e:
            print(f"❌ Error processing MQTT message: {e}")
            self.stats['errors'] += 1

    def preprocess_message(self, raw_message):
        """Normalize and enrich agent messages"""
        try:
            payload = raw_message['raw_payload']
            mqtt_topic = raw_message['mqtt_topic']
            
            # Extract agent type from topic
            agent_type = "unknown"
            for agent, topic_pattern in self.AGENT_TOPICS.items():
                if topic_pattern.replace('#', '') in mqtt_topic:
                    agent_type = f"{agent}_agent"
                    break
            
            # Create normalized message
            normalized_message = {
                'message_id': str(uuid.uuid4()),
                'agent_id': payload.get('agent_id', 'unknown'),
                'agent_type': agent_type,
                'gateway_id': raw_message['gateway_id'],
                'received_timestamp_utc': raw_message['received_at'],
                'sequence_number': self.get_next_sequence(),
                'telemetry_type': 'anomaly' if payload.get('anomalies') else 'telemetry',
                'severity': self.calculate_severity(payload),
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
            return None

    def calculate_severity(self, payload):
        """Calculate message severity based on content"""
        score = payload.get('security_score', 100)
        anomalies = payload.get('anomalies', [])
        
        if score < 30 or any('critical' in str(anom).lower() for anom in anomalies):
            return 'critical'
        elif score < 60 or len(anomalies) > 0:
            return 'warning'
        else:
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
            self.stats['errors'] += 1
        else:
            self.stats['messages_forwarded'] += 1
            print(f'✅ Message delivered to {msg.topic()} [{msg.partition()}]')

    def forward_to_kafka(self, normalized_message):
        """Forward normalized message to Kafka"""
        try:
            topic = normalized_message['kafka_topic']
            message_key = normalized_message['agent_id']
            message_value = json.dumps(normalized_message).encode('utf-8')
            
            self.kafka_producer.produce(
                topic,
                key=message_key,
                value=message_value,
                callback=self.kafka_delivery_report
            )
            
            # Trigger delivery reports
            self.kafka_producer.poll(0)
            
            print(f"📤 Forwarded to Kafka [{topic}]: {normalized_message['agent_id']}")
            
        except Exception as e:
            print(f"❌ Error forwarding to Kafka: {e}")
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
                    self.stats['last_processed'] = datetime.utcnow().isoformat()
                
                self.message_buffer.task_done()
                
            except Empty:
                # No messages in buffer, continue
                continue
            except Exception as e:
                print(f"❌ Error in buffer processing: {e}")
                self.stats['errors'] += 1

    def publish_gateway_health(self):
        """Publish gateway health status periodically"""
        while True:
            try:
                health_status = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'status': 'healthy',
                    'stats': self.stats,
                    'buffer_size': self.message_buffer.qsize(),
                    'agent_count': len(self.agent_status)
                }
                
                self.mqtt_client.publish(
                    "security/gateway/health",
                    json.dumps(health_status),
                    retain=True
                )
                
                print(f"❤️  Gateway Health | Buffer: {self.message_buffer.qsize()} | "
                      f"Received: {self.stats['messages_received']} | "
                      f"Forwarded: {self.stats['messages_forwarded']}")
                      
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
