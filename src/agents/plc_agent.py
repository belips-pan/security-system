import json
import time
import os
import random
import requests

from mqtt_agent import MQTTAgent

class PLCAPI:
    def __init__(self):
        self.firmware_checksum = "a7c3e9f1b24d9..."
        self.state = "RUN"
        self.registers = {
            "motor_speed_rpm": 1200,
            "conveyor_temp_c": 85,
        }
        self.last_command_source = "192.168.1.10"
        self.remote_logins_24h = 0
        self.unauthorized_logins = 0

    def get_firmware_checksum(self):
        if random.random() < 0.01:
            return "xyz123abc456..."
        return self.firmware_checksum

    def get_operational_state(self):
        if random.random() < 0.02:
            return "STOP"
        return self.state

    def get_register_values(self):
        if random.random() < 0.05:
            self.registers["conveyor_temp_c"] = 90
        return self.registers

    def get_last_command_source(self):
        if random.random() < 0.1:
            return "10.0.0.50"
        return self.last_command_source

    def check_remote_access_attempts(self):
        self.remote_logins_24h = random.randint(0, 5)
        if self.remote_logins_24h > 0 and random.random() < 0.5:
            self.unauthorized_logins = 1
        return {"total": self.remote_logins_24h, "unauthorized": self.unauthorized_logins}

class PLCAgent:
    def __init__(self, config_file_path, backend_url="http://localhost:5000"):
        self.plc = PLCAPI()
        self.config = self.load_config(config_file_path)
        self.agent_id = self.config.get("agent_id", "UNKNOWN_PLC")
        self.api_key = self.config.get("api_key")  # Προσθήκη API Key
        self.backend_url = backend_url
        self.last_telemetry_time = 0

        # MQTT publisher: the edge gateway's Kafka/health pipeline only
        # receives data via MQTT, so telemetry is published there in
        # addition to the direct HTTP POST to the backend below.
        self.mqtt_agent = MQTTAgent(
            agent_id=self.agent_id,
            agent_type="plc",
            mqtt_broker=os.getenv("MQTT_BROKER_HOST", "localhost"),
            mqtt_port=int(os.getenv("MQTT_BROKER_PORT", 1883)),
            mqtt_username=self.config.get("mqtt_username"),
            mqtt_password=self.config.get("mqtt_password")
        )

        print(f"🔌 PLC Agent '{self.agent_id}' initialized with API Key")

    def load_config(self, config_file_path):
        if not os.path.exists(config_file_path):
            print(f"❌ Error: Configuration file not found at {config_file_path}")
            return {}
        try:
            with open(config_file_path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"❌ Error: Invalid JSON in configuration file.")
            return {}

    def _risk_points(self, sub_score_key, default):
        """Read a configured risk-point deduction from
        scoring_model.sub_scores, falling back to `default` if the config
        doesn't define it (mirrors the pattern robot_agent.py already uses
        for its own scoring)."""
        return (
            self.config.get("scoring_model", {})
                .get("sub_scores", {})
                .get(sub_score_key, {})
                .get("risk_points", default)
        )

    def collect_and_score(self):
        payload = {
            "agent_id": self.agent_id,
            "timestamp": int(time.time()),
            "anomalies": [],
            "metrics": {},
            "security_score": 100
        }
        current_score = 100

        # Firmware Integrity
        checksum = self.plc.get_firmware_checksum()
        baseline = self.config["metrics"]["logic_and_firmware_integrity"]["baseline_checksum"]
        if checksum != baseline:
            payload["anomalies"].append("firmware_checksum_mismatch")
            current_score -= self._risk_points("logic_integrity", 30)

        # Operational State
        state = self.plc.get_operational_state()
        expected_state = self.config["metrics"]["operational_state_changes"]["current_state"]
        if state != expected_state:
            payload["anomalies"].append("unexpected_state_change")
            current_score -= self._risk_points("state_change", 25)

        # Register Values
        registers = self.plc.get_register_values()
        payload["metrics"]["registers"] = registers

        register_risk_points = self._risk_points("register_anomaly", 20)
        for reg, value in registers.items():
            expected_range = self.config["metrics"]["register_tag_value_anomalies"]["monitored_registers"][reg]["expected_range"]
            if not (expected_range[0] <= value <= expected_range[1]):
                payload["anomalies"].append(f"register_{reg}_out_of_range")
                current_score -= register_risk_points

        # Communication Security
        source_ip = self.plc.get_last_command_source()
        if source_ip not in self.config["metrics"]["communication_auditing"]["allowed_ips"]:
            payload["anomalies"].append("unauthorized_command_source")
            current_score -= self._risk_points("communication_auditing", 35)

        # Remote Access - use the configured unauthorized_attempts_threshold
        # instead of a hardcoded "> 0" check.
        access_attempts = self.plc.check_remote_access_attempts()
        unauthorized_threshold = self.config.get("metrics", {}).get("remote_access", {}).get(
            "unauthorized_attempts_threshold", 1
        )
        if access_attempts["unauthorized"] >= unauthorized_threshold:
            payload["anomalies"].append("unauthorized_remote_access")
            current_score -= self._risk_points("remote_access", 40)

        payload["security_score"] = max(0, current_score)
        return payload

    def send_to_backend(self, data):
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
                print(f"✅ PLC data sent successfully - Score: {data['security_score']}")
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

    def send_with_retry(self, data, max_retries=3, backoff_seconds=5):
        """Retry sending the SAME payload on failure instead of silently
        dropping it and generating fresh data next cycle."""
        attempt = 0
        while True:
            if self.send_to_backend(data):
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
        print(f"🚀 Starting PLC Agent '{self.agent_id}'...")

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

            if current_time - self.last_telemetry_time >= self.config.get("telemetry_frequency_seconds", 15):
                payload = self.collect_and_score()
                score = payload["security_score"]

                status = "SECURE" if score >= 80 else "MODERATE RISK" if score >= 50 else "HIGH RISK"
                print(f"📊 PLC Status: {status} | Score: {score} | Anomalies: {len(payload['anomalies'])}")

                # Publish to MQTT so the edge gateway's Kafka/health
                # pipeline actually receives this agent's data.
                self.mqtt_agent.publish_telemetry(payload)

                success = self.send_with_retry(payload)
                if success:
                    self.last_telemetry_time = current_time

            time.sleep(1)

if __name__ == "__main__":
    agent = PLCAgent('../configs/plc_config.json')
    try:
        agent.run()
    except KeyboardInterrupt:
        print("\n🛑 PLC agent stopped.")
