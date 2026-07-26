import json
import time
import os
import random
import requests

from mqtt_agent import MQTTAgent

class RobotAPI:
    def __init__(self):
        self.joint_angles = [0, 0, 0, 0, 0, 0]
        self.current_speed = 0.0
        self.current_payload = 0.0
        self.current_tool = "gripper"
        self.current_x = 2.5
        self.current_y = 2.5
        self.is_e_stop_active = False
        self.sensor_signal_lost = 0
        self.battery_voltage = 24.0

    def get_joint_angles(self):
        return [angle + random.uniform(-2, 2) for angle in self.joint_angles]

    def get_command_details(self):
        return {
            "source_ip": random.choice(["192.168.10.20", "10.10.10.1", "172.16.0.5"]),
            "command": "move_to_position",
            "speed": random.uniform(0.5, 2.0),
            "payload": random.uniform(5.0, 15.0),
            "tool_change": random.choice([None, "welding_torch", "screwdriver"])
        }

    def get_position(self):
        return {"x": random.uniform(0, 6), "y": random.uniform(0, 6)}

    def get_sensor_status(self):
        if random.random() < 0.05:
            return {"proximity_sensor": "false_positive" if random.random() > 0.5 else "signal_lost"}
        return {"proximity_sensor": "ok"}

    def get_battery_voltage(self):
        return self.battery_voltage + random.uniform(-2, 2)

    def get_safety_status(self):
        """Simulate the two highest-risk safety-override conditions.
        Updates self.is_e_stop_active in place (previously set once in
        __init__ and never touched again) and returns whether an
        interlock-bypass attempt was detected this cycle."""
        self.is_e_stop_active = random.random() < 0.02
        interlock_bypass_attempt = random.random() < 0.01
        return {"interlock_bypass_attempt": interlock_bypass_attempt}

    def get_signal_status(self):
        """Simulate occasional loss of the robot's general telemetry/sensor
        signal. Updates self.sensor_signal_lost in place (previously set
        once in __init__ and never touched again)."""
        self.sensor_signal_lost = 1 if random.random() < 0.03 else 0
        return self.sensor_signal_lost

    def get_operational_status(self):
        """Simulate operational-integrity signals: an unexpected shutdown
        event and a mechanical stress reading."""
        return {
            "unexpected_shutdown": random.random() < 0.02,
            "mechanical_stress": random.uniform(0, 100)
        }

    def get_vision_status(self):
        """Simulate the robot's vision system: an object mismatch (seeing
        something other than the expected workpiece/tool) or a tampering
        event on the camera itself."""
        return {
            "object_mismatch": random.random() < 0.03,
            "tamper_detected": random.random() < 0.01
        }

class RobotAgent:
    def __init__(self, config_file_path, backend_url="http://localhost:5000"):
        self.robot = RobotAPI()
        self.config = self.load_config(config_file_path)
        self.agent_id = self.config.get("agent_id", "UNKNOWN_ROBOT")
        self.api_key = self.config.get("api_key")  # Προσθήκη API Key
        self.backend_url = backend_url
        self.last_telemetry_time = 0

        # MQTT publisher: the edge gateway's Kafka/health pipeline only
        # receives data via MQTT, so telemetry is published there in
        # addition to the direct HTTP POST to the backend below.
        self.mqtt_agent = MQTTAgent(
            agent_id=self.agent_id,
            agent_type="robot",
            mqtt_broker=os.getenv("MQTT_BROKER_HOST", "localhost"),
            mqtt_port=int(os.getenv("MQTT_BROKER_PORT", 1883)),
            mqtt_username=self.config.get("mqtt_username"),
            mqtt_password=self.config.get("mqtt_password")
        )

        print(f"🤖 Robot Agent '{self.agent_id}' initialized with API Key")

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

    def collect_and_score(self):
        """Collects data, scores anomalies, and returns the payload."""
        robot_data = {
            "agent_id": self.agent_id,
            "timestamp": int(time.time()),
            "anomalies": [],
            "metrics": {},
            "security_score": 100
        }
        current_score = 100

        # Command anomaly checks
        command_details = self.robot.get_command_details()
        if command_details["source_ip"] not in self.config["metrics"]["network_security"]["allowed_ips"]:
            risk = self.config["metrics"]["command_anomalies"]["unauthorized_source"]["risk_points"]
            current_score -= risk
            robot_data["anomalies"].append("unauthorized_command_source")

        if command_details["speed"] > self.config["metrics"]["command_anomalies"]["out_of_range_commands"]["max_speed_mps"]:
            risk = self.config["metrics"]["command_anomalies"]["out_of_range_commands"]["risk_points"]
            current_score -= risk
            robot_data["anomalies"].append("speed_exceeded")

        # Behavior deviation checks
        robot_pos = self.robot.get_position()
        workcell = self.config["metrics"]["behavior_deviation"]["workcell_boundary_meters"]
        if not (workcell["x_min"] <= robot_pos["x"] <= workcell["x_max"] and
                workcell["y_min"] <= robot_pos["y"] <= workcell["y_max"]):
            risk = self.config["metrics"]["behavior_deviation"]["workcell_boundary_meters"]["risk_points"]
            current_score -= risk
            robot_data["anomalies"].append("out_of_bounds_movement")

        # Sensor integrity checks - proximity sensor (already implemented)
        sensor_status = self.robot.get_sensor_status()
        if sensor_status["proximity_sensor"] != "ok":
            risk = self.config["metrics"]["sensor_integrity"]["proximity_sensor"]["risk_points"]
            current_score -= risk
            robot_data["anomalies"].append("proximity_sensor_anomaly")

        # Sensor integrity - general signal loss (previously
        # RobotAPI.sensor_signal_lost was set but never read anywhere)
        self.robot.get_signal_status()
        if self.robot.sensor_signal_lost:
            vision_cfg = self.config.get("metrics", {}).get("sensor_integrity", {}).get("vision_system", {})
            risk = vision_cfg.get("risk_points", 30)
            current_score -= risk
            robot_data["anomalies"].append("sensor_signal_lost")

        # Sensor integrity - vision system (previously defined in config
        # but never implemented at all)
        vision_cfg = self.config.get("metrics", {}).get("sensor_integrity", {}).get("vision_system", {})
        vision_status = self.robot.get_vision_status()
        vision_risk = vision_cfg.get("risk_points", 30)
        if vision_cfg.get("object_mismatch_alert") and vision_status["object_mismatch"]:
            current_score -= vision_risk
            robot_data["anomalies"].append("vision_object_mismatch")
        if vision_cfg.get("tamper_detection") and vision_status["tamper_detected"]:
            current_score -= vision_risk
            robot_data["anomalies"].append("vision_tamper_detected")

        # Safety overrides - the two highest-risk items in the config,
        # previously never implemented at all.
        safety_cfg = self.config.get("metrics", {}).get("safety_overrides", {})
        safety_status = self.robot.get_safety_status()

        estop_cfg = safety_cfg.get("unauthorized_estop", {})
        if estop_cfg.get("enabled") and self.robot.is_e_stop_active:
            current_score -= estop_cfg.get("risk_points", 100)
            robot_data["anomalies"].append("unauthorized_estop")

        interlock_cfg = safety_cfg.get("interlock_bypass_attempt", {})
        if interlock_cfg.get("enabled") and safety_status["interlock_bypass_attempt"]:
            current_score -= interlock_cfg.get("risk_points", 100)
            robot_data["anomalies"].append("interlock_bypass_attempt")

        # Operational integrity - previously never implemented at all.
        op_cfg = self.config.get("metrics", {}).get("operational_integrity", {})
        battery_voltage = self.robot.get_battery_voltage()

        battery_cfg = op_cfg.get("battery_voltage_min", {})
        battery_min = battery_cfg.get("value")
        if battery_min is not None and battery_voltage < battery_min:
            current_score -= battery_cfg.get("risk_points", 15)
            robot_data["anomalies"].append("battery_voltage_below_minimum")

        operational_status = self.robot.get_operational_status()

        shutdown_cfg = op_cfg.get("unexpected_shutdown", {})
        if shutdown_cfg.get("enabled") and operational_status["unexpected_shutdown"]:
            current_score -= shutdown_cfg.get("risk_points", 40)
            robot_data["anomalies"].append("unexpected_shutdown")

        stress_cfg = op_cfg.get("mechanical_stress_threshold", {})
        stress_threshold = stress_cfg.get("value")
        if stress_threshold is not None and operational_status["mechanical_stress"] > stress_threshold:
            current_score -= stress_cfg.get("risk_points", 20)
            robot_data["anomalies"].append("mechanical_stress_exceeded")

        # Update final score
        robot_data["security_score"] = max(0, current_score)
        robot_data["metrics"] = {
            "position": robot_pos,
            "sensor_status": sensor_status,
            "sensor_signal_lost": bool(self.robot.sensor_signal_lost),
            "vision_status": vision_status,
            "battery_voltage": battery_voltage,
            "command_details": command_details,
            "safety_status": {
                "is_e_stop_active": self.robot.is_e_stop_active,
                "interlock_bypass_attempt": safety_status["interlock_bypass_attempt"]
            },
            "operational_status": operational_status
        }

        return robot_data

    def send_to_backend(self, data):
        """Sends data to the backend API with API Key authentication"""
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
                print(f"✅ Data sent successfully to backend - Score: {data['security_score']}")
                return True
            elif response.status_code == 401:
                print(f"❌ Authentication failed - Invalid API Key")
                return False
            else:
                print(f"❌ Failed to send data: {response.status_code} - {response.text}")
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
        """Main loop for the Robot Agent"""
        print(f"🚀 Starting Robot Agent '{self.agent_id}'...")

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

                # Decision logic based on security score
                score = payload["security_score"]
                if score >= 80:
                    status = "SECURE"
                elif score >= 50:
                    status = "MODERATE RISK"
                else:
                    status = "HIGH RISK"

                print(f"📊 Status: {status} | Score: {score} | Anomalies: {len(payload['anomalies'])}")

                # Publish to MQTT so the edge gateway's Kafka/health
                # pipeline actually receives this agent's data.
                self.mqtt_agent.publish_telemetry(payload)

                # Send to backend (retrying the same payload on transient failures)
                success = self.send_with_retry(payload)
                if success:
                    self.last_telemetry_time = current_time

            time.sleep(1)

if __name__ == "__main__":
    agent = RobotAgent('../configs/robot_config.json')
    try:
        agent.run()
    except KeyboardInterrupt:
        print("\n🛑 Agent stopped by user.")
