import json
import time
import os
import random
import requests

class CameraAgent:
    def __init__(self, config_file_path, backend_url="http://localhost:5000"):
        self.agent_id = None
        self.config = self.load_config(config_file_path)
        self.api_key = self.config.get("api_key")  # Προσθήκη API Key
        self.backend_url = backend_url
        self.last_telemetry_time = 0
        print(f"📷 Camera Agent '{self.agent_id}' initialized with API Key")

    def load_config(self, config_file_path):
        if not os.path.exists(config_file_path):
            print(f"❌ Error: Configuration file not found at {config_file_path}")
            return {}
        try:
            with open(config_file_path, 'r') as f:
                config = json.load(f)
                self.agent_id = config.get("agent_id")
                return config
        except json.JSONDecodeError:
            print(f"❌ Error: Invalid JSON in configuration file.")
            return {}

    def detect_events(self):
        events = []
        security_score = 100
        
        # Motion Detection
        motion_enabled = self.config['security_features']['motion_detection']['enabled']
        if motion_enabled and random.random() < 0.05:
            events.append("motion_detected")

        # Tampering Detection
        tampering_enabled = self.config['security_features']['tampering_detection']['enabled']
        if tampering_enabled and random.random() < 0.01:
            events.append("tampering_detected")
            security_score -= 30

        # Object Detection
        object_detection_enabled = self.config['security_features']['object_detection']['enabled']
        if object_detection_enabled and random.random() < 0.03:
            detected_object = random.choice(
                self.config['security_features']['object_detection']['unauthorized_objects']
            )
            events.append(f"unauthorized_object_{detected_object}")
            security_score -= 40

        return events, security_score

    def send_to_backend(self, data, is_alert=False):
        """Send data to backend with API Key authentication"""
        try:
            headers = {
                'X-API-Key': self.api_key,
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f"{self.backend_url}/api/telemetry", 
                json=data, 
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                alert_status = "ALERT" if is_alert else "data"
                print(f"✅ Camera {alert_status} sent successfully - Score: {data['security_score']}")
                return True
            elif response.status_code == 401:
                print(f"❌ Authentication failed - Invalid API Key")
                return False
            else:
                print(f"❌ Failed to send data: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Connection error: {e}")
            return False

    def test_connection(self):
        """Test connection to backend with API Key"""
        try:
            headers = {'X-API-Key': self.api_key}
            response = requests.get(
                f"{self.backend_url}/api/auth/verify", 
                headers=headers,
                timeout=5
            )
            if response.status_code == 200:
                print(f"✅ Connection test successful - Authenticated as: {response.json().get('authenticated_as', 'unknown')}")
                return True
            else:
                print(f"❌ Connection test failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Connection test error: {e}")
            return False

    def run(self):
        print("🚀 Starting Camera Agent...")
        
        # Test connection first
        if not self.test_connection():
            print("❌ Cannot start agent - Connection test failed")
            return
        
        while True:
            # Detect security events
            detected_events, security_score = self.detect_events()
            
            # Prepare telemetry data
            telemetry_data = {
                "agent_id": self.agent_id,
                "timestamp": int(time.time()),
                "anomalies": detected_events,
                "security_score": security_score,
                "metrics": {
                    "events_detected": len(detected_events),
                    "camera_status": "operational"
                }
            }

            # Send data
            is_alert = len(detected_events) > 0
            success = self.send_to_backend(telemetry_data, is_alert=is_alert)
            
            if detected_events:
                print(f"📷 Camera Alert | Events: {detected_events} | Score: {security_score}")
            
            if not success:
                print("⏳ Retrying in 5 seconds...")
                time.sleep(5)
                continue
                
            # Sleep until next cycle
            time.sleep(self.config.get('telemetry_frequency_seconds', 60))

if __name__ == "__main__":
    agent = CameraAgent('../configs/camera_config.json')
    try:
        agent.run()
    except KeyboardInterrupt:
        print("\n🛑 Camera agent stopped.")
