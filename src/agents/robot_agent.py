import json
import time
import os
import random
import requests

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

class RobotAgent:
    def __init__(self, config_file_path, backend_url="http://localhost:5000"):
        self.robot = RobotAPI()
        self.config = self.load_config(config_file_path)
        self.agent_id = self.config["agent_id"]
        self.api_key = self.config["api_key"]  # Προσθήκη API Key
        self.backend_url = backend_url
        self.last_telemetry_time = 0
        print(f"🤖 Robot Agent '{self.agent_id}' initialized with API Key")

    def load_config(self, config_file_path):
        if not os.path.exists(config_file_path):
            print(f"❌ Error: Configuration file not found at {config_file_path}")
            return {}
        with open(config_file_path, 'r') as f:
            return json.load(f)

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

        # Sensor integrity checks
        sensor_status = self.robot.get_sensor_status()
        if sensor_status["proximity_sensor"] != "ok":
            risk = self.config["metrics"]["sensor_integrity"]["proximity_sensor"]["risk_points"]
            current_score -= risk
            robot_data["anomalies"].append("proximity_sensor_anomaly")
        
        # Update final score
        robot_data["security_score"] = max(0, current_score)
        robot_data["metrics"] = {
            "position": robot_pos,
            "sensor_status": sensor_status,
            "battery_voltage": self.robot.get_battery_voltage(),
            "command_details": command_details
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
                print(f"❌ Authentication failed - Invalid API Key: {self.api_key[:10]}...")
                return False
            else:
                print(f"❌ Failed to send data: {response.status_code} - {response.text}")
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
        """Main loop for the Robot Agent"""
        print(f"🚀 Starting Robot Agent '{self.agent_id}'...")
        
        # Test connection first
        if not self.test_connection():
            print("❌ Cannot start agent - Connection test failed")
            return
        
        while True:
            current_time = int(time.time())
            
            if current_time - self.last_telemetry_time >= self.config["telemetry_frequency_seconds"]:
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
                
                # Send to backend
                success = self.send_to_backend(payload)
                if success:
                    self.last_telemetry_time = current_time
                else:
                    print("⏳ Retrying in 5 seconds...")
                    time.sleep(5)  # Wait before retry
            
            time.sleep(1)

if __name__ == "__main__":
    agent = RobotAgent('../configs/robot_config.json')
    try:
        agent.run()
    except KeyboardInterrupt:
        print("\n🛑 Agent stopped by user.")
