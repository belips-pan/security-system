import json
import time
import os
import psutil
import requests

class IoTAgent:
    def __init__(self, config_file_path, backend_url="http://localhost:5000"):
        self.agent_id = None
        self.config = self.load_config(config_file_path)
        self.api_key = self.config.get("api_key")  # Προσθήκη API Key
        self.backend_url = backend_url
        self.last_sent_time = 0
        print(f"📟 IoT Agent '{self.agent_id}' initialized with API Key")

    def load_config(self, config_file_path):
        if not os.path.exists(config_file_path):
            print(f"❌ Error: Configuration file not found at {config_file_path}")
            return {}
        try:
            with open(config_file_path, 'r') as f:
                config = json.load(f)
                self.agent_id = config.get("agent_id")
                print(f"✅ IoT Agent {self.agent_id} loaded successfully.")
                return config
        except json.JSONDecodeError:
            print(f"❌ Error: Invalid JSON in configuration file.")
            return {}

    def collect(self):
        data = {
            "agent_id": self.agent_id,
            "timestamp": int(time.time()),
            "anomalies": [],
            "metrics": {},
            "security_score": 100
        }

        # System metrics
        if self.config['metrics']['system_metrics']['collect']:
            system_metrics = self._get_system_metrics()
            data["metrics"]["system"] = system_metrics
            
            # Check thresholds
            params = self.config['metrics']['system_metrics']['parameters']
            if system_metrics["cpu_percent"] > params['cpu_threshold_percent']:
                data["anomalies"].append("high_cpu_usage")
                data["security_score"] -= 20
                
            if system_metrics["memory_used_mb"] > params['memory_threshold_mb']:
                data["anomalies"].append("high_memory_usage")
                data["security_score"] -= 20

        # Network connections
        if self.config['metrics']['network_connections']['collect']:
            network_data = self._get_network_connections()
            data["metrics"]["network"] = network_data
            
            for conn in network_data:
                if not conn['is_allowed']:
                    data["anomalies"].append(f"unauthorized_connection_{conn['dest_ip']}")
                    data["security_score"] -= 30

        # Process list
        if self.config['metrics']['process_list']['collect']:
            process_data = self._get_process_list()
            data["metrics"]["processes"] = process_data
            
            for proc in process_data:
                if not proc['is_allowed']:
                    data["anomalies"].append(f"unauthorized_process_{proc['name']}")
                    data["security_score"] -= 25

        data["security_score"] = max(0, data["security_score"])
        return data

    def _get_system_metrics(self):
        return {
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "memory_used_mb": psutil.virtual_memory().used / (1024 * 1024),
            "disk_usage_percent": psutil.disk_usage('/').percent
        }

    def _get_network_connections(self):
        connections = []
        allowed_destinations = self.config['metrics']['network_connections']['parameters'].get('allowed_destinations', [])
        
        for conn in psutil.net_connections():
            if conn.status == "ESTABLISHED" and conn.raddr:
                remote_ip = conn.raddr.ip
                is_allowed = remote_ip in allowed_destinations
                
                connections.append({
                    "src_ip": conn.laddr.ip,
                    "dest_ip": remote_ip,
                    "dest_port": conn.raddr.port,
                    "is_allowed": is_allowed
                })
        return connections

    def _get_process_list(self):
        processes = []
        allowed_processes = self.config['metrics']['process_list']['parameters'].get('allowed_processes', [])

        for proc in psutil.process_iter(['name', 'pid']):
            proc_name = proc.info['name']
            is_allowed = proc_name in allowed_processes
            
            processes.append({
                "name": proc_name,
                "pid": proc.info['pid'],
                "is_allowed": is_allowed
            })
        return processes

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
                print(f"✅ IoT data sent successfully - Score: {data['security_score']}")
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
        if not self.config:
            return
            
        print("🚀 Starting IoT Agent...")
        
        # Test connection first
        if not self.test_connection():
            print("❌ Cannot start agent - Connection test failed")
            return
        
        while True:
            current_time = int(time.time())
            
            # Collect and send data at configured intervals
            if current_time - self.last_sent_time >= self.config['metrics']['system_metrics']['frequency_seconds']:
                data = self.collect()
                print(f"📊 IoT Status | Score: {data['security_score']} | Anomalies: {len(data['anomalies'])}")
                
                success = self.send_to_backend(data)
                if success:
                    self.last_sent_time = current_time
                else:
                    print("⏳ Retrying in 5 seconds...")
                    time.sleep(5)
                    continue
            
            time.sleep(1)

if __name__ == "__main__":
    agent = IoTAgent('../configs/iot_config.json')
    try:
        agent.run()
    except KeyboardInterrupt:
        print("\n🛑 IoT agent stopped.")
