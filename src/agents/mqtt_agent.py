import paho.mqtt.client as mqtt
import json
import time
import uuid

class MQTTAgent:
    def __init__(self, agent_id, agent_type, mqtt_broker="localhost", mqtt_port=1883):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.mqtt_broker = mqtt_broker
        self.mqtt_port = mqtt_port
        
        # MQTT client
        self.mqtt_client = mqtt.Client(client_id=f"{agent_type}_{agent_id}_{uuid.uuid4().hex[:8]}")
        self.mqtt_client.on_connect = self.on_mqtt_connect
        self.mqtt_client.on_disconnect = self.on_mqtt_disconnect
        
        # Topics
        self.telemetry_topic = f"security/agents/{agent_type}/{agent_id}/telemetry"
        self.status_topic = f"security/agents/{agent_type}/{agent_id}/status"
        
    def on_mqtt_connect(self, client, userdata, flags, rc):
        if rc == 0:
            print(f"✅ {self.agent_id} connected to MQTT broker")
            # Publish online status
            self.publish_status("online")
        else:
            print(f"❌ {self.agent_id} MQTT connection failed: {rc}")
            
    def on_mqtt_disconnect(self, client, userdata, rc):
        print(f"⚠️  {self.agent_id} MQTT disconnected: {rc}")
        
    def connect_mqtt(self):
        try:
            self.mqtt_client.connect(self.mqtt_broker, self.mqtt_port, 60)
            self.mqtt_client.loop_start()
            return True
        except Exception as e:
            print(f"❌ MQTT connection error: {e}")
            return False
            
    def publish_telemetry(self, telemetry_data):
        """Publish telemetry data to MQTT"""
        try:
            payload = {
                'agent_id': self.agent_id,
                'agent_type': self.agent_type,
                'timestamp': int(time.time()),
                **telemetry_data
            }
            
            self.mqtt_client.publish(
                self.telemetry_topic,
                json.dumps(payload),
                qos=1  # At least once delivery
            )
            print(f"📤 {self.agent_id} telemetry published")
            return True
            
        except Exception as e:
            print(f"❌ Telemetry publish error: {e}")
            return False
            
    def publish_status(self, status):
        """Publish agent status"""
        try:
            payload = {
                'agent_id': self.agent_id,
                'status': status,
                'timestamp': int(time.time())
            }
            
            self.mqtt_client.publish(
                self.status_topic,
                json.dumps(payload),
                retain=True
            )
        except Exception as e:
            print(f"❌ Status publish error: {e}")
