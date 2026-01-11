import json
import time
import os
import random
import requests

class DroneAgent:
    def __init__(self, config_file_path, backend_url="http://localhost:5000"):
        self.config = self.load_config(config_file_path)
        self.agent_id = self.config.get("agent_id")
        self.api_key = self.config.get("api_key")  # Προσθήκη API Key
        self.backend_url = backend_url
        self.last_telemetry_time = 0
        print(f"🚁 Drone Agent '{self.agent_id}' initialized with API Key")

    def load_config(self, path):
        if not os.path.exists(path):
            print(f"❌ Config file not found: {path}")
            return {}
        with open(path, 'r') as f:
            return json.load(f)

    def collect_and_score(self):
        data = {
            "agent_id": self.agent_id,
            "timestamp": int(time.time()),
            "anomalies": [],
            "metrics": {},
            "security_score": 100
        }

        # Simulate GPS position
        gps_data = {
            "lat": round(random.uniform(37.95, 38.00), 6),
            "lon": round(random.uniform(23.65, 23.75), 6),
            "alt": random.uniform(5, 30)
        }
        data["metrics"]["gps"] = gps_data

        # Check geofence violation
        geofence = self.config["metrics"]["geofence"]["allowed_area"]
        if not (geofence["lat_min"] <= gps_data["lat"] <= geofence["lat_max"] and
                geofence["lon_min"] <= gps_data["lon"] <= geofence["lon_max"]):
            data["anomalies"].append("geofence_violation")
            data["security_score"] -= 50

        # Simulate battery level
        battery_level = random.uniform(0, 100)
        data["metrics"]["battery_level"] = battery_level
        if battery_level < self.config["metrics"]["battery"]["min_threshold"]:
            data["anomalies"].append("low_battery")
            data["security_score"] -= 20

        data["security_score"] = max(0, data["security_score"])
        return data

    def send_to_backend(self, payload):
        """Send data to backend with API Key authentication"""
        try:
            headers = {
                'X-API-Key': self.api_key,
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f"{self.backend_url}/api/telemetry", 
                json=payload, 
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                print(f"✅ Drone data sent successfully - Score: {payload['security_score']}")
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
        print(f"🚀 Starting Drone Agent '{self.agent_id}'...")
        
        # Test connection first
        if not self.test_connection():
            print("❌ Cannot start agent - Connection test failed")
            return
            
        while True:
            current_time = int(time.time())
            if current_time - self.last_telemetry_time >= self.config.get("telemetry_frequency_seconds", 10):
                payload = self.collect_and_score()
                print(f"📊 Drone Status | Score: {payload['security_score']} | Anomalies: {len(payload['anomalies'])}")
                
                success = self.send_to_backend(payload)
                if success:
                    self.last_telemetry_time = current_time
                else:
                    print("⏳ Retrying in 5 seconds...")
                    time.sleep(5)
                    
            time.sleep(1)

if __name__ == "__main__":
    agent = DroneAgent('../configs/drone_config.json')
    try:
        agent.run()
    except KeyboardInterrupt:
        print("🛑 Drone agent stopped.")
