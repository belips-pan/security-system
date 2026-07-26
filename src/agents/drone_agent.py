import json
import time
import os
import random
import requests

from mqtt_agent import MQTTAgent

class DroneAgent:
    def __init__(self, config_file_path, backend_url="http://localhost:5000"):
        self.config = self.load_config(config_file_path)
        self.agent_id = self.config.get("agent_id")
        self.api_key = self.config.get("api_key")  # Προσθήκη API Key
        self.backend_url = backend_url
        self.last_telemetry_time = 0

        # MQTT publisher: the edge gateway's Kafka/health pipeline only
        # receives data via MQTT, so telemetry is published there in
        # addition to the direct HTTP POST to the backend below.
        self.mqtt_agent = MQTTAgent(
            agent_id=self.agent_id or "unknown",
            agent_type="drone",
            mqtt_broker=os.getenv("MQTT_BROKER_HOST", "localhost"),
            mqtt_port=int(os.getenv("MQTT_BROKER_PORT", 1883)),
            mqtt_username=self.config.get("mqtt_username"),
            mqtt_password=self.config.get("mqtt_password")
        )

        print(f"🚁 Drone Agent '{self.agent_id}' initialized with API Key")

    def load_config(self, path):
        if not os.path.exists(path):
            print(f"❌ Config file not found: {path}")
            return {}
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"❌ Error: Invalid JSON in configuration file.")
            return {}

    def _simulate_gps_position(self):
        """Simulate a GPS fix. Usually within the configured geofence, but
        occasionally (the less-common case) excursing just outside it, so
        the geofence violation check downstream has real signal - the
        previous implementation sampled from exactly the allowed_area
        bounds, so a violation could never actually occur."""
        geofence = self.config["metrics"]["geofence"]["allowed_area"]
        lat_min, lat_max = geofence["lat_min"], geofence["lat_max"]
        lon_min, lon_max = geofence["lon_min"], geofence["lon_max"]
        lat_margin = (lat_max - lat_min) * 0.15
        lon_margin = (lon_max - lon_min) * 0.15

        if random.random() < 0.90:
            lat = round(random.uniform(lat_min, lat_max), 6)
            lon = round(random.uniform(lon_min, lon_max), 6)
        else:
            # Excursion: sample just outside the allowed bounds on a
            # random side, within 15% of the allowed area's own range.
            if random.random() < 0.5:
                lat = round(random.uniform(lat_min - lat_margin, lat_min), 6)
            else:
                lat = round(random.uniform(lat_max, lat_max + lat_margin), 6)
            if random.random() < 0.5:
                lon = round(random.uniform(lon_min - lon_margin, lon_min), 6)
            else:
                lon = round(random.uniform(lon_max, lon_max + lon_margin), 6)

        return {"lat": lat, "lon": lon, "alt": random.uniform(5, 30)}

    def collect_and_score(self):
        data = {
            "agent_id": self.agent_id,
            "timestamp": int(time.time()),
            "anomalies": [],
            "metrics": {},
            "security_score": 100
        }

        # Simulate GPS position
        gps_data = self._simulate_gps_position()
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

    def send_with_retry(self, payload, max_retries=3, backoff_seconds=5):
        """Retry sending the SAME payload on failure instead of silently
        dropping it and generating fresh data next cycle."""
        attempt = 0
        while True:
            if self.send_to_backend(payload):
                return True
            attempt += 1
            if attempt > max_retries:
                print(f"❌ Giving up on this payload after {max_retries} retries; "
                      f"will collect fresh data next cycle")
                return False
            print(f"⏳ Retry {attempt}/{max_retries} for same payload in {backoff_seconds}s...")
            time.sleep(backoff_seconds)

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

    def test_connection_with_retry(self, max_attempts=6, base_backoff=2, max_backoff=60):
        """Retry the startup connectivity check with exponential backoff
        instead of giving up permanently on the first failure."""
        for attempt in range(1, max_attempts + 1):
            if self.test_connection():
                return True
            if attempt == max_attempts:
                break
            backoff = min(base_backoff * (2 ** (attempt - 1)), max_backoff)
            print(f"⏳ Connection attempt {attempt}/{max_attempts} failed, retrying in {backoff}s...")
            time.sleep(backoff)
        return False

    def run(self):
        print(f"🚀 Starting Drone Agent '{self.agent_id}'...")

        if not self.config:
            print("❌ Cannot start agent - configuration is missing or invalid")
            return

        # Test connection first (with retry/backoff)
        if not self.test_connection_with_retry():
            print("❌ Cannot start agent - Connection test failed")
            return

        if not self.mqtt_agent.connect_mqtt():
            print("⚠️  MQTT connection failed - continuing with HTTP-only telemetry")

        while True:
            current_time = int(time.time())
            if current_time - self.last_telemetry_time >= self.config.get("telemetry_frequency_seconds", 10):
                payload = self.collect_and_score()
                print(f"📊 Drone Status | Score: {payload['security_score']} | Anomalies: {len(payload['anomalies'])}")

                # Publish to MQTT so the edge gateway's Kafka/health
                # pipeline actually receives this agent's data.
                self.mqtt_agent.publish_telemetry(payload)

                success = self.send_with_retry(payload)
                if success:
                    self.last_telemetry_time = current_time

            time.sleep(1)

if __name__ == "__main__":
    agent = DroneAgent('../configs/drone_config.json')
    try:
        agent.run()
    except KeyboardInterrupt:
        print("🛑 Drone agent stopped.")
