import json
import time
import os
import psutil
import requests

from mqtt_agent import MQTTAgent

class IoTAgent:
    def __init__(self, config_file_path, backend_url="http://localhost:5000"):
        self.agent_id = None
        self.config = self.load_config(config_file_path)
        self.api_key = self.config.get("api_key")  # Προσθήκη API Key
        self.backend_url = backend_url
        self.last_sent_time = 0

        # MQTT publisher: the edge gateway's Kafka/health pipeline only
        # receives data via MQTT, so telemetry is published there in
        # addition to the direct HTTP POST to the backend below.
        self.mqtt_agent = MQTTAgent(
            agent_id=self.agent_id or "unknown",
            agent_type="iot",
            mqtt_broker=os.getenv("MQTT_BROKER_HOST", "localhost"),
            mqtt_port=int(os.getenv("MQTT_BROKER_PORT", 1883)),
            mqtt_username=self.config.get("mqtt_username"),
            mqtt_password=self.config.get("mqtt_password")
        )

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
                if conn.get('is_blocked_port'):
                    data["anomalies"].append(f"blocked_port_connection_{conn['dest_port']}")
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
        net_params = self.config['metrics']['network_connections']['parameters']
        allowed_destinations = net_params.get('allowed_destinations', [])
        blocked_ports = set(net_params.get('blocked_ports', []))

        try:
            raw_connections = psutil.net_connections()
        except (psutil.AccessDenied, psutil.Error, OSError) as e:
            print(f"⚠️  Could not enumerate network connections: {e}")
            return connections

        for conn in raw_connections:
            try:
                if conn.status == "ESTABLISHED" and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    is_allowed = remote_ip in allowed_destinations
                    is_blocked_port = remote_port in blocked_ports

                    connections.append({
                        "src_ip": conn.laddr.ip,
                        "dest_ip": remote_ip,
                        "dest_port": remote_port,
                        "is_allowed": is_allowed,
                        "is_blocked_port": is_blocked_port
                    })
            except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied) as e:
                # The connection's owning process may have exited between
                # enumeration and inspection - skip it rather than crash.
                print(f"⚠️  Skipping connection entry ({e})")
                continue
        return connections

    def _get_process_list(self):
        processes = []
        allowed_processes = self.config['metrics']['process_list']['parameters'].get('allowed_processes', [])

        try:
            proc_iter = psutil.process_iter(['name', 'pid'])
        except (psutil.AccessDenied, psutil.Error, OSError) as e:
            print(f"⚠️  Could not enumerate processes: {e}")
            return processes

        for proc in proc_iter:
            try:
                proc_name = proc.info['name']
                is_allowed = proc_name in allowed_processes

                processes.append({
                    "name": proc_name,
                    "pid": proc.info['pid'],
                    "is_allowed": is_allowed
                })
            except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied) as e:
                # Process may have exited (or become a zombie / be
                # inaccessible) between iteration and inspection - this is
                # a normal, racy OS condition, so skip it rather than
                # crash the whole agent.
                print(f"⚠️  Skipping process entry ({e})")
                continue
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
        if not self.config:
            return

        print("🚀 Starting IoT Agent...")

        # Test connection first (with retry/backoff)
        if not self.test_connection_with_retry():
            print("❌ Cannot start agent - Connection test failed")
            return

        if not self.mqtt_agent.connect_mqtt():
            print("⚠️  MQTT connection failed - continuing with HTTP-only telemetry")

        while True:
            current_time = int(time.time())

            # Collect and send data at configured intervals
            if current_time - self.last_sent_time >= self.config['metrics']['system_metrics']['frequency_seconds']:
                try:
                    data = self.collect()
                except Exception as e:
                    # One bad iteration (e.g. a transient OS enumeration
                    # error not already caught below) should not kill the
                    # whole agent process.
                    print(f"❌ Error collecting telemetry, skipping this cycle: {e}")
                    time.sleep(1)
                    continue

                print(f"📊 IoT Status | Score: {data['security_score']} | Anomalies: {len(data['anomalies'])}")

                # Publish to MQTT so the edge gateway's Kafka/health
                # pipeline actually receives this agent's data.
                self.mqtt_agent.publish_telemetry(data)

                success = self.send_with_retry(data)
                if success:
                    self.last_sent_time = current_time

            time.sleep(1)

if __name__ == "__main__":
    agent = IoTAgent('../configs/iot_config.json')
    try:
        agent.run()
    except KeyboardInterrupt:
        print("\n🛑 IoT agent stopped.")
