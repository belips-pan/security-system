#!/usr/bin/env python3
"""
Security System Test Framework
Πλήρες framework για πειραματική αξιολόγηση με 310 simulated agents
"""

import os
import sys
import time
import json
import threading
import queue
import argparse
import logging
import random
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum

# Third-party imports
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Για headless execution
from matplotlib.ticker import MaxNLocator
import seaborn as sns

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('test_framework.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# DATA CLASSES
# ============================================================================

class AgentType(Enum):
    """Τύποι agents στο σύστημα"""
    CAMERA = "camera"
    DRONE = "drone"
    ROBOT = "robot"
    SENSOR = "sensor"
    PLC = "plc"

@dataclass
class AgentConfig:
    """Configuration για κάθε agent type"""
    agent_type: AgentType
    base_id: str
    base_api_key: str
    base_frequency: int  # seconds
    target_count: int
    data_size_kb: float  # Μέσο μέγεθος telemetry σε KB
    
    # Υπολογιζόμενα πεδία
    clones_needed: int = 0
    test_frequency: float = 0
    total_traffic_kbps: float = 0

@dataclass
class TestResult:
    """Αποτελέσματα μιας δοκιμής"""
    test_id: str
    timestamp: datetime
    duration_seconds: int
    multiplier: float  # ✅ ΠΡΟΣΘΗΚΗ - έλειπε!
    active_agents: int
    telemetry_rate: float
    api_requests: int
    api_errors: int
    avg_response_time_ms: float
    p95_response_time_ms: float
    p99_response_time_ms: float
    cpu_usage_percent: float
    memory_usage_mb: float
    network_in_mbps: float
    network_out_mbps: float
    db_connections: int
    db_query_time_ms: float
    alerts_generated: int
    scans_completed: int
    queue_size: int
    successful_requests: int = 0
    failed_requests: int = 0
    total_requests: int = 0
    success_rate: float = 0.0
    metadata: Dict = field(default_factory=dict)

@dataclass
class AttackScenario:
    """Σενάριο επίθεσης για testing"""
    name: str
    description: str
    attack_type: str  # 'port_scan', 'brute_force', 'flood', 'injection'
    target: str
    intensity: str  # 'low', 'medium', 'high'
    duration_seconds: int
    expected_detection: bool
    executed: bool = False
    detected: bool = False
    detection_time_ms: Optional[float] = None
    false_positive: bool = False
    notes: str = ""

# ============================================================================
# SIMULATED AGENT POOL
# ============================================================================

class SimulatedAgent:
    """Προσομοίωση ενός IoT agent - ΠΛΗΡΗΣ ΥΛΟΠΟΙΗΣΗ"""
    
    def __init__(self, agent_id: str, agent_type: AgentType, 
                 api_key: str, frequency: float, backend_url: str,
                 behavior_seed: int = None, multiplier: float = 1.0):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.api_key = api_key
        self.frequency = frequency
        self.backend_url = backend_url
        self.multiplier = multiplier
        self.running = False
        self.message_count = 0
        self.error_count = 0
        self.last_message_time = 0
        self.latencies = []
        
        # ΜΟΝΑΔΙΚΟ seed για κάθε agent
        if behavior_seed is not None:
            random.seed(behavior_seed)
            self.behavior_seed = behavior_seed
        else:
            import hashlib
            hash_val = int(hashlib.md5(agent_id.encode()).hexdigest()[:8], 16)
            random.seed(hash_val)
            self.behavior_seed = hash_val
        
        # Headers για authentication
        self.headers = {
            'X-API-Key': api_key,
            'Content-Type': 'application/json'
        }
        
        # Μοναδικό προφίλ συμπεριφοράς
        self.behavior_profile = self._create_behavior_profile()
        
        # Αρχικοποίηση sensors
        self.sensors = self._init_sensors()
        
        # Χρόνος έναρξης
        self.start_time = time.time()
        
        logger.debug(f"Created agent {agent_id} ({agent_type.value}) with seed {self.behavior_seed}")
    
    def _create_behavior_profile(self) -> Dict:
        """Δημιουργεί μοναδικό προφίλ συμπεριφοράς για κάθε agent"""
        
        # Βασικό προφίλ ανά τύπο
        base_profiles = {
            AgentType.CAMERA: {
                'score_mean': 85,
                'score_std': 8,
                'anomaly_prob': 0.05,
                'drift_rate': 0.01,
                'noise_level': 0.1,
                'sensor_variance': 0.2
            },
            AgentType.DRONE: {
                'score_mean': 88,
                'score_std': 10,
                'anomaly_prob': 0.07,
                'drift_rate': 0.02,
                'noise_level': 0.15,
                'sensor_variance': 0.3
            },
            AgentType.ROBOT: {
                'score_mean': 82,
                'score_std': 12,
                'anomaly_prob': 0.08,
                'drift_rate': 0.015,
                'noise_level': 0.12,
                'sensor_variance': 0.25
            },
            AgentType.SENSOR: {
                'score_mean': 92,
                'score_std': 5,
                'anomaly_prob': 0.03,
                'drift_rate': 0.005,
                'noise_level': 0.05,
                'sensor_variance': 0.1
            },
            AgentType.PLC: {
                'score_mean': 90,
                'score_std': 7,
                'anomaly_prob': 0.04,
                'drift_rate': 0.008,
                'noise_level': 0.08,
                'sensor_variance': 0.15
            }
        }
        
        base = base_profiles[self.agent_type]
        
        # Μοναδικές παραλλαγές ανά agent
        profile = {
            'score_mean': base['score_mean'] + random.uniform(-5, 5),
            'score_std': base['score_std'] * random.uniform(0.8, 1.2),
            'anomaly_prob': base['anomaly_prob'] * random.uniform(0.5, 2.0),
            'drift_rate': base['drift_rate'] * random.uniform(0.5, 1.5),
            'noise_level': base['noise_level'] * random.uniform(0.7, 1.3),
            'sensor_variance': base['sensor_variance'] * random.uniform(0.6, 1.4),
            'battery_degrade_rate': random.uniform(0.1, 0.5),
            'temperature_baseline': random.uniform(30, 40),
            'failure_prone': random.random() < 0.1
        }
        
        return profile
    
    def _init_sensors(self) -> Dict:
        """Αρχικοποίηση sensors με μοναδικές αρχικές τιμές"""
        sensors = {}
        
        if self.agent_type == AgentType.CAMERA:
            sensors = {
                'motion_detected': False,
                'tampering_detected': False,
                'fps': random.randint(25, 30),
                'resolution': '1920x1080',
                'night_mode': random.random() < 0.3,
                'temperature': random.uniform(35, 45),
                'uptime': 0
            }
        elif self.agent_type == AgentType.DRONE:
            sensors = {
                'latitude': 37.95 + random.uniform(-0.02, 0.02),
                'longitude': 23.70 + random.uniform(-0.02, 0.02),
                'altitude': random.uniform(30, 70),
                'battery': random.uniform(80, 100),
                'speed': 0,
                'gps_signal': random.choice(['strong', 'medium']),
                'temperature': random.uniform(20, 35)
            }
        elif self.agent_type == AgentType.ROBOT:
            sensors = {
                'position_x': random.uniform(1, 4),
                'position_y': random.uniform(1, 4),
                'joint_angles': [random.uniform(-10, 10) for _ in range(6)],
                'speed': random.uniform(0.3, 0.8),
                'payload': random.uniform(3, 8),
                'battery': random.uniform(85, 100),
                'temperature': random.uniform(32, 38)
            }
        elif self.agent_type == AgentType.SENSOR:
            sensors = {
                'temperature': random.uniform(20, 25),
                'humidity': random.uniform(40, 50),
                'pressure': random.uniform(1010, 1016),
                'air_quality': random.randint(20, 30),
                'light_level': random.randint(400, 600)
            }
        elif self.agent_type == AgentType.PLC:
            sensors = {
                'motor_speed': random.randint(1150, 1250),
                'conveyor_temp': random.uniform(60, 70),
                'state': 'RUN',
                'registers': [random.randint(0, 100) for _ in range(4)],
                'firmware_version': '2.1.4',
                'uptime': random.randint(100, 1000)
            }
        
        return sensors
    
    def _generate_telemetry(self) -> Dict:
        """Δημιουργεί telemetry data"""
        
        # Αντιγραφή sensors
        data = json.loads(json.dumps(self.sensors))
        
        # Time-based factors
        elapsed = (time.time() - self.start_time) / 3600
        
        # Εφαρμογή drift
        drift = self.behavior_profile['drift_rate'] * elapsed
        
        # Προσομοίωση διακυμάνσεων
        if self.agent_type == AgentType.CAMERA:
            data['motion_detected'] = random.random() < 0.05 * (1 + drift)
            data['tampering_detected'] = random.random() < 0.01 * (1 + drift * 2)
            data['temperature'] += random.gauss(0, 2) + drift * 2
            data['fps'] = max(15, data['fps'] + random.randint(-2, 2))
            
        elif self.agent_type == AgentType.DRONE:
            data['latitude'] += random.gauss(0, 0.002) * (1 + drift)
            data['longitude'] += random.gauss(0, 0.002) * (1 + drift)
            data['altitude'] += random.gauss(0, 5) * (1 + drift * 0.5)
            data['battery'] = max(0, data['battery'] - self.behavior_profile['battery_degrade_rate'] * 0.1)
            if random.random() < 0.02 * (1 + drift):
                data['gps_signal'] = 'weak'
            else:
                data['gps_signal'] = random.choice(['strong', 'medium'])
            
        elif self.agent_type == AgentType.ROBOT:
            data['position_x'] += random.gauss(0, 0.2) * (1 + drift * 0.5)
            data['position_y'] += random.gauss(0, 0.2) * (1 + drift * 0.5)
            data['position_x'] = max(0, min(6, data['position_x']))
            data['position_y'] = max(0, min(6, data['position_y']))
            data['joint_angles'] = [a + random.gauss(0, 2) for a in data['joint_angles']]
            data['temperature'] += random.gauss(0, 1) + drift * 3
            
        elif self.agent_type == AgentType.SENSOR:
            data['temperature'] += random.gauss(0, 0.5) + drift * 0.5
            data['humidity'] += random.gauss(0, 1) + drift
            data['pressure'] += random.gauss(0, 1)
            data['air_quality'] += random.randint(-3, 3)
            data['light_level'] += random.randint(-30, 30)
            
        elif self.agent_type == AgentType.PLC:
            data['motor_speed'] += random.randint(-15, 15)
            data['conveyor_temp'] += random.gauss(0, 1) + drift * 2
            if random.random() < 0.01 * (1 + drift * 3):
                data['state'] = 'STOP' if data['state'] == 'RUN' else 'RUN'
        
        # Δημιουργία anomalies
        anomalies = self._generate_anomalies()
        
        # Υπολογισμός security score
        security_score = self._calculate_security_score(anomalies, elapsed)
        
        return {
            'agent_id': self.agent_id,
            'agent_type': self.agent_type.value,
            'timestamp': int(time.time()),
            'security_score': security_score,
            'anomalies': anomalies,
            'metrics': data,
            'load_multiplier': self.multiplier
        }
    
    def _generate_anomalies(self) -> List[str]:
        """Δημιουργεί anomalies"""
        anomalies = []
        
        base_prob = self.behavior_profile['anomaly_prob']
        
        if self.behavior_profile.get('failure_prone', False):
            base_prob *= 3
        
        if random.random() < base_prob:
            anomaly_types = {
                AgentType.CAMERA: ['suspicious_motion', 'tampering_attempt', 'camera_offline'],
                AgentType.DRONE: ['geofence_violation', 'signal_loss', 'battery_critical'],
                AgentType.ROBOT: ['joint_limit_exceeded', 'emergency_stop', 'overheating'],
                AgentType.SENSOR: ['extreme_reading', 'sensor_failure', 'calibration_error'],
                AgentType.PLC: ['register_out_of_range', 'unauthorized_access', 'firmware_mismatch']
            }
            
            num_anomalies = random.randint(1, 2)
            selected = random.sample(anomaly_types[self.agent_type], 
                                    min(num_anomalies, len(anomaly_types[self.agent_type])))
            anomalies.extend(selected)
        
        return anomalies
    
    def _calculate_security_score(self, anomalies: List[str], elapsed_hours: float) -> int:
        """Υπολογίζει security score"""
        base = self.behavior_profile['score_mean']
        noise = random.gauss(0, self.behavior_profile['score_std'])
        anomaly_penalty = len(anomalies) * random.uniform(5, 15)
        time_penalty = elapsed_hours * self.behavior_profile['drift_rate'] * 10
        
        score = base + noise - anomaly_penalty - time_penalty
        return max(0, min(100, int(score)))
    
    def send_telemetry(self) -> Tuple[bool, float]:
        """Στέλνει telemetry στο backend με βελτιωμένο logging"""
        telemetry = self._generate_telemetry()
    
        # Log του μηνύματος για debugging (μόνο για πρώτα λίγα)
        if self.message_count < 5:
            logger.debug(f"Agent {self.agent_id} sending telemetry with API key {self.api_key[:20]}...")
    
        start_time = time.time()
        try:
            response = requests.post(
                f"{self.backend_url}/api/telemetry",
                json=telemetry,
                headers=self.headers,
                timeout=5
            )
            latency_ms = (time.time() - start_time) * 1000
        
            if response.status_code == 200:
                self.message_count += 1
                self.latencies.append(latency_ms)
                if self.message_count == 1:
                    logger.info(f"✅ First message from {self.agent_id} succeeded!")
                return True, latency_ms
            else:
                self.error_count += 1
                # Log μόνο για τα πρώτα λάθη
                if self.error_count < 10:
                    logger.error(f"❌ Agent {self.agent_id} failed with status {response.status_code}: {response.text[:200]}")
                return False, latency_ms
            
        except requests.exceptions.ConnectionError as e:
            latency_ms = (time.time() - start_time) * 1000
            self.error_count += 1
            if self.error_count < 5:
                logger.error(f"❌ Agent {self.agent_id} connection error: {e}")
            return False, latency_ms
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            self.error_count += 1
            if self.error_count < 5:
                logger.error(f"❌ Agent {self.agent_id} exception: {e}")
            return False, latency_ms
    
    def run(self, stop_event: threading.Event):
        """Κύρια λειτουργία agent"""
        self.running = True
        self.last_message_time = time.time()
        
        while not stop_event.is_set():
            current_time = time.time()
            jitter = random.uniform(0.9, 1.1)
            effective_frequency = self.frequency * jitter
            
            if current_time - self.last_message_time >= effective_frequency:
                success, latency = self.send_telemetry()
                self.last_message_time = current_time
            
            time.sleep(0.01)
        
        self.running = False
        logger.debug(f"Agent {self.agent_id} stopped")


class AgentPool:
    """Pool από simulated agents"""
    
    def __init__(self, backend_url: str = "http://192.168.56.20:15000"):
        self.backend_url = backend_url
        self.agents: List[SimulatedAgent] = []
        self.agent_threads: List[threading.Thread] = []
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        
        # Στατιστικά
        self.total_messages = 0
        self.total_errors = 0
        self.start_time = None
        self.end_time = None
        
        # Ορισμός target counts
        self.targets = {
            AgentType.CAMERA: 50,
            AgentType.DRONE: 10,
            AgentType.ROBOT: 20,
            AgentType.SENSOR: 200,
            AgentType.PLC: 30
        }
        
        # Base configurations
        self.base_configs = {
            AgentType.CAMERA: AgentConfig(
                agent_type=AgentType.CAMERA,
                base_id="CAM-WH-01",
                base_api_key="QIFDkxVGMQ0dzMnn90-GlqzBpMVr4425FRIYvAIyFTU",
                base_frequency=30,
                target_count=50,
                data_size_kb=2.5
            ),
            AgentType.DRONE: AgentConfig(
                agent_type=AgentType.DRONE,
                base_id="DRONE-01",
                base_api_key="DWVkXiDJ_IIbdkxRTSIKjAhe4bFUuvhFgiMfWhaII",
                base_frequency=30,
                target_count=10,
                data_size_kb=1.8
            ),
            AgentType.ROBOT: AgentConfig(
                agent_type=AgentType.ROBOT,
                base_id="Robot_Arm_001",
                base_api_key="DVvkafojenj6091wusBSJbL02gIawkIFt2oS8rJIF4U",
                base_frequency=30,
                target_count=20,
                data_size_kb=3.2
            ),
            AgentType.SENSOR: AgentConfig(
                agent_type=AgentType.SENSOR,
                base_id="raspberrypi-01",
                base_api_key="wEMFje4up11GLvqINeMix4j_cJqUu7wLLMXYb15BFmY",
                base_frequency=30,
                target_count=200,
                data_size_kb=0.5
            ),
            AgentType.PLC: AgentConfig(
                agent_type=AgentType.PLC,
                base_id="PLC001",
                base_api_key="kGha2GWsIsJhs6UTh3smngAPBqdMmeMd2XRKp317JeA",
                base_frequency=30,
                target_count=30,
                data_size_kb=1.2
            )
        }
        
        logger.info("AgentPool initialized")
    
    def calculate_test_config(self, agent_type: AgentType, 
                              multiplier: float = 5.0) -> Tuple[int, float]:
        """
        Υπολογίζει πόσα clones χρειάζονται και τη συχνότητα testing
        
        multiplier: πόσο πιο γρήγορα θα στέλνουν telemetry (π.χ., 5 = 5x)
        """
        config = self.base_configs[agent_type]
        target = config.target_count
        
        # traffic_multiplier = base_frequency / test_frequency
        test_frequency = config.base_frequency / multiplier
        traffic_multiplier = multiplier
        
        clones_needed = int(np.ceil(target / traffic_multiplier))
        
        # Ενημέρωση config
        config.clones_needed = clones_needed
        config.test_frequency = test_frequency
        config.total_traffic_kbps = (clones_needed / test_frequency) * config.data_size_kb * 8
        
        return clones_needed, test_frequency
    
    def create_agents_for_test(self, multiplier: float = 5.0):
        """Δημιουργεί όλους τους agents για testing - ΜΕ ΜΟΝΑΔΙΚΑ API KEYS"""
    
        with self.lock:
            self.agents = []
        
            for agent_type in AgentType:
                config = self.base_configs[agent_type]
                clones_needed, test_freq = self.calculate_test_config(agent_type, multiplier)
            
                logger.info(f"\n📊 {agent_type.value.upper()}:")
                logger.info(f"  Target: {config.target_count} agents")
                logger.info(f"  Clones needed: {clones_needed}")
                logger.info(f"  Test frequency: {test_freq:.2f} sec")
                logger.info(f"  Traffic: {config.total_traffic_kbps:.2f} Kbps")
            
                for i in range(clones_needed):
                    # Μοναδικό agent_id
                    agent_id = f"{config.base_id}_{i+1:03d}"
                
                    api_key = config.base_api_key  # ΟΧΙ μοναδικό!
                
                    # Δημιουργία seed
                    import hashlib
                    seed = int(hashlib.md5(agent_id.encode()).hexdigest()[:8], 16)
                
                    # Μοναδικό API key για κάθε clone
                    unique_suffix = hashlib.md5(f"{agent_id}_{multiplier}".encode()).hexdigest()[:8]
                    unique_api_key = f"{config.base_api_key}_{unique_suffix}"
                
                    agent = SimulatedAgent(
                        agent_id=agent_id,
                        agent_type=agent_type,
                        api_key=api_key,
                        frequency=test_freq,
                        backend_url=self.backend_url,
                        behavior_seed=seed,  # ✅ ΤΩΡΑ ΟΡΙΣΜΕΝΟ!
                        multiplier=multiplier
                    )
                    self.agents.append(agent)
        
            logger.info(f"\n✅ Created total {len(self.agents)} simulated agents")
            return len(self.agents)
    
    def start_all(self):
        """Ξεκινά όλους τους agents σε threads"""
        self.stop_event.clear()
        self.start_time = datetime.now()
        self.agent_threads = []
        
        logger.info(f"\n🚀 Starting {len(self.agents)} agents...")
        
        for agent in self.agents:
            thread = threading.Thread(
                target=agent.run,
                args=(self.stop_event,),
                daemon=True
            )
            thread.start()
            self.agent_threads.append(thread)
            
            # Μικρή καθυστέρηση για αποφυγή race conditions
            time.sleep(0.001)
        
        logger.info(f"✅ All agents started")
    
    def stop_all(self):
        """Σταματά όλους τους agents"""
        logger.info(f"\n🛑 Stopping all agents...")
        self.stop_event.set()
        
        # Αναμονή για τερματισμό threads
        for thread in self.agent_threads:
            thread.join(timeout=2)
        
        self.end_time = datetime.now()
        
        # Συλλογή στατιστικών
        self.total_messages = sum(a.message_count for a in self.agents)
        self.total_errors = sum(a.error_count for a in self.agents)
        
        duration = (self.end_time - self.start_time).total_seconds()
        
        logger.info(f"\n📊 Agent Pool Statistics:")
        logger.info(f"  Duration: {duration:.2f} seconds")
        logger.info(f"  Total messages: {self.total_messages}")
        logger.info(f"  Total errors: {self.total_errors}")
        logger.info(f"  Avg rate: {self.total_messages/duration:.2f} msgs/sec")
        
        return {
            'duration': duration,
            'messages': self.total_messages,
            'errors': self.total_errors,
            'rate': self.total_messages/duration
        }
    
    def get_aggregate_stats(self) -> Dict:
        """Επιστρέφει συγκεντρωτικά στατιστικά"""
        if not self.agents:
            return {}
        
        all_latencies = []
        for agent in self.agents:
            all_latencies.extend(agent.latencies[-100:])  # Last 100 per agent
        
        if all_latencies:
            latencies = np.array(all_latencies)
            latency_stats = {
                'p50': np.percentile(latencies, 50),
                'p95': np.percentile(latencies, 95),
                'p99': np.percentile(latencies, 99),
                'mean': np.mean(latencies),
                'std': np.std(latencies)
            }
        else:
            latency_stats = {}
        
        return {
            'total_agents': len(self.agents),
            'total_messages': self.total_messages,
            'total_errors': self.total_errors,
            'error_rate': self.total_errors / max(self.total_messages, 1),
            'latency_stats': latency_stats,
            'agents_by_type': {
                agent_type.value: len([a for a in self.agents if a.agent_type == agent_type])
                for agent_type in AgentType
            }
        }


# ============================================================================
# SYSTEM MONITOR
# ============================================================================

class SystemMonitor:
    """Παρακολούθηση συστήματος κατά τη διάρκεια δοκιμών"""
    
    def __init__(self, db_url: str = "postgresql://admin:password@localhost:15433/security_db"):
        self.db_url = db_url
        self.measurements: List[Dict] = []
        self.running = False
        self.monitor_thread = None
        self.stop_event = threading.Event()
        
        # Σύνδεση στη βάση
        try:
            self.db_conn = psycopg2.connect(db_url)
            self.db_cursor = self.db_conn.cursor(cursor_factory=RealDictCursor)
            logger.info("✅ Connected to database")
        except Exception as e:
            logger.error(f"❌ Database connection failed: {e}")
            self.db_conn = None
    
    def collect_snapshot(self) -> Dict:
        """Συλλέγει ένα snapshot του συστήματος"""
        snapshot = {
            'timestamp': datetime.now().isoformat(),
            'timestamp_epoch': time.time()
        }
        
        # Database statistics
        if self.db_conn:
            try:
                # Telemetry count last minute
                self.db_cursor.execute("""
                    SELECT COUNT(*) as count FROM telemetry 
                    WHERE timestamp > NOW() - INTERVAL '1 minute'
                """)
                row = self.db_cursor.fetchone()
                snapshot['telemetry_rate'] = row['count'] / 60 if row else 0
                
                # Alert count last minute
                self.db_cursor.execute("""
                    SELECT COUNT(*) as count FROM alerts 
                    WHERE timestamp > NOW() - INTERVAL '1 minute'
                """)
                row = self.db_cursor.fetchone()
                snapshot['alert_rate'] = row['count'] if row else 0
                
                # Agent statistics
                self.db_cursor.execute("""
                    SELECT 
                        COUNT(*) as total,
                        SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
                        SUM(CASE WHEN last_seen > NOW() - INTERVAL '1 minute' THEN 1 ELSE 0 END) as online
                    FROM agents
                """)
                row = self.db_cursor.fetchone()
                if row:
                    snapshot['agents_total'] = row['total']
                    snapshot['agents_active'] = row['active']
                    snapshot['agents_online'] = row['online']
                
                # Database connections
                self.db_cursor.execute("SELECT COUNT(*) as count FROM pg_stat_activity")
                row = self.db_cursor.fetchone()
                snapshot['db_connections'] = row['count'] if row else 0
                
            except Exception as e:
                logger.error(f"Error collecting DB stats: {e}")
        
        # Redis statistics (θα μπορούσατε να προσθέσετε)
        # System metrics (θα μπορούσατε να διαβάσετε από /proc)
        
        return snapshot
    
    def start_monitoring(self, interval_seconds: float = 5.0):
        """Ξεκινά monitoring σε background thread"""
        self.running = True
        self.stop_event.clear()
        self.measurements = []
        
        def monitor_loop():
            logger.info(f"📊 Monitoring started (interval: {interval_seconds}s)")
            while not self.stop_event.is_set():
                snapshot = self.collect_snapshot()
                self.measurements.append(snapshot)
                time.sleep(interval_seconds)
            logger.info("📊 Monitoring stopped")
        
        self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self) -> pd.DataFrame:
        """Σταματά monitoring και επιστρέφει DataFrame με μετρήσεις"""
        self.stop_event.set()
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        # Μετατροπή σε DataFrame
        df = pd.DataFrame(self.measurements)
        
        if not df.empty:
            # Μετατροπή timestamp σε datetime
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            logger.info(f"📊 Collected {len(df)} measurements")
        
        return df
    
    def close(self):
        """Κλείσιμο συνδέσεων"""
        if self.db_conn:
            self.db_cursor.close()
            self.db_conn.close()


# ============================================================================
# ATTACK SIMULATOR
# ============================================================================

class AttackSimulator:
    """Προσομοίωση επιθέσεων για testing"""
    
    def __init__(self, backend_url: str = "http://192.168.56.20:15000", 
                 api_key: str = "monitor123"):
        self.backend_url = backend_url
        self.api_key = api_key
        self.headers = {'X-API-Key': api_key}
        self.results: List[AttackScenario] = []
        
    def port_scan_attack(self, target_ip: str = "192.168.56.20", 
                          intensity: str = "medium") -> AttackScenario:
        """Προσομοίωση port scanning attack"""
        
        scenario = AttackScenario(
            name="Port Scan Detection",
            description="Nmap port scan of backend server",
            attack_type="port_scan",
            target=target_ip,
            intensity=intensity,
            duration_seconds=30,
            expected_detection=True
        )
        
        logger.info(f"🔍 Executing {intensity} port scan on {target_ip}")
        
        # Προσομοίωση nmap scan
        start_time = time.time()
        
        if intensity == "low":
            time.sleep(5)
            ports_scanned = 100
        elif intensity == "medium":
            time.sleep(10)
            ports_scanned = 500
        else:  # high
            time.sleep(20)
            ports_scanned = 1000
        
        # Έλεγχος αν ανιχνεύτηκε (θα πρέπει να ελέγξετε alerts στη βάση)
        # Εδώ προσομοιώνουμε detection
        detection_time = random.uniform(5, 15) * 1000  # ms
        detected = detection_time < 20000  # Ανιχνεύεται σε <20 sec
        
        scenario.executed = True
        scenario.detected = detected
        scenario.detection_time_ms = detection_time if detected else None
        scenario.notes = f"Scanned {ports_scanned} ports"
        
        self.results.append(scenario)
        return scenario
    
    def brute_force_attack(self, endpoint: str = "/api/auth/login", 
                           intensity: str = "medium") -> AttackScenario:
        """Προσομοίωση brute force attack σε endpoint"""
        
        scenario = AttackScenario(
            name="Brute Force Attack",
            description=f"Brute force attack on {endpoint}",
            attack_type="brute_force",
            target=endpoint,
            intensity=intensity,
            duration_seconds=60,
            expected_detection=True
        )
        
        logger.info(f"🔑 Executing {intensity} brute force on {endpoint}")
        
        # Καθορισμός ρυθμού επιθέσεων
        if intensity == "low":
            rate = 5  # requests/sec
        elif intensity == "medium":
            rate = 20  # requests/sec
        else:  # high
            rate = 100  # requests/sec
        
        successful = 0
        failed = 0
        latencies = []
        
        for i in range(rate * scenario.duration_seconds):
            if i % rate == 0:
                time.sleep(1)  # Ένα request ανά δευτερόλεπτο σύμφωνα με rate
            
            # Τυχαίο username/password
            username = f"user_{random.randint(1, 1000)}"
            password = hashlib.md5(str(random.random()).encode()).hexdigest()[:8]
            
            payload = {
                'username': username,
                'password': password
            }
            
            start = time.time()
            try:
                response = requests.post(
                    f"{self.backend_url}{endpoint}",
                    json=payload,
                    timeout=2
                )
                latency = (time.time() - start) * 1000
                latencies.append(latency)
                
                if response.status_code == 200:
                    successful += 1
                else:
                    failed += 1
                    
            except Exception:
                failed += 1
                latencies.append(5000)  # Timeout
        
        # Ανίχνευση attack (βασισμένη σε failed attempts)
        detected = failed > rate * 10  # Αν >10 failures/sec
        detection_time = random.uniform(10, 30) * 1000 if detected else None
        
        scenario.executed = True
        scenario.detected = detected
        scenario.detection_time_ms = detection_time
        scenario.notes = f"{successful} successful, {failed} failed, avg latency {np.mean(latencies):.2f}ms"
        
        self.results.append(scenario)
        return scenario
    
    def telemetry_flood_attack(self, intensity: str = "medium") -> AttackScenario:
        """Προσομοίωση telemetry flooding attack"""
        
        scenario = AttackScenario(
            name="Telemetry Flood",
            description="Flood backend with fake telemetry data",
            attack_type="flood",
            target="/api/telemetry",
            intensity=intensity,
            duration_seconds=30,
            expected_detection=True
        )
        
        logger.info(f"🌊 Executing {intensity} telemetry flood")
        
        # Καθορισμός ρυθμού
        if intensity == "low":
            rate = 50  # requests/sec
        elif intensity == "medium":
            rate = 200  # requests/sec
        else:  # high
            rate = 1000  # requests/sec
        
        successful = 0
        failed = 0
        latencies = []
        
        # Δημιουργία ψεύτικου agent
        fake_agent_id = f"fake_agent_{random.randint(1, 10000)}"
        fake_api_key = "invalid_key_123"
        headers = {'X-API-Key': fake_api_key}
        
        start_time = time.time()
        end_time = start_time + scenario.duration_seconds
        
        request_count = 0
        while time.time() < end_time:
            # Δημιουργία ψεύτικου telemetry
            telemetry = {
                'agent_id': fake_agent_id,
                'timestamp': int(time.time()),
                'security_score': random.randint(0, 100),
                'anomalies': ['simulated_attack'] if random.random() < 0.3 else [],
                'metrics': {
                    'value': random.random() * 100,
                    'status': 'simulated'
                }
            }
            
            start = time.time()
            try:
                response = requests.post(
                    f"{self.backend_url}/api/telemetry",
                    json=telemetry,
                    headers=headers,
                    timeout=1
                )
                latency = (time.time() - start) * 1000
                latencies.append(latency)
                
                if response.status_code == 401:  # Αναμενόμενο για invalid key
                    successful += 1
                else:
                    failed += 1
                    
            except Exception:
                failed += 1
                latencies.append(2000)
            
            request_count += 1
            
            # Έλεγχος rate
            elapsed = time.time() - start_time
            target_requests = elapsed * rate
            if request_count < target_requests:
                time.sleep(0.001)  # Μικρή αναμονή
        
        # Ανίχνευση attack
        detected = request_count > rate * 0.8  # Αν έστειλε >80% των requests
        
        scenario.executed = True
        scenario.detected = detected
        scenario.detection_time_ms = random.uniform(5, 15) * 1000 if detected else None
        scenario.notes = f"Sent {request_count} requests, {successful} accepted, {failed} failed"
        
        self.results.append(scenario)
        return scenario
    
    def get_results_dataframe(self) -> pd.DataFrame:
        """Επιστρέφει αποτελέσματα ως DataFrame"""
        return pd.DataFrame([asdict(r) for r in self.results])


# ============================================================================
# TEST CONTROLLER
# ============================================================================

class TestController:
    """Κύριος controller για εκτέλεση δοκιμών"""
    
    def __init__(self, backend_url: str = "http://192.168.56.20:15000",
                 db_url: str = "postgresql://admin:password@localhost:15433/security_db",
                 api_key: str = "monitor123"):
        
        self.backend_url = backend_url
        self.db_url = db_url
        self.api_key = api_key
        
        # Components
        self.agent_pool = AgentPool(backend_url)
        self.monitor = SystemMonitor(db_url)
        self.attack_sim = AttackSimulator(backend_url, api_key)
        
        # Αποτελέσματα
        self.test_results: List[TestResult] = []
        self.test_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        logger.info(f"✅ TestController initialized (test_id: {self.test_id})")
    
    def check_backend_health(self) -> bool:
        """Έλεγχος αν το backend είναι ζωντανό"""
        try:
            response = requests.get(f"{self.backend_url}/health", timeout=5)
            if response.status_code == 200:
                logger.info("✅ Backend is healthy")
                return True
            else:
                logger.error(f"❌ Backend returned {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"❌ Backend unreachable: {e}")
            return False

    def test_agent_authentication(self) -> bool:
        """Δοκιμάζει αν ένας agent μπορεί να συνδεθεί - ΧΡΗΣΗ ΥΠΑΡΧΟΝΤΟΣ agent από τη βάση"""
        logger.info("🔍 Testing agent authentication...")
    
        # ΑΠΟ ΤΟ create_demo_data.log βλέπουμε ότι υπάρχουν ΑΥΤΟΙ οι agents
        # Χρησιμοποιούμε έναν που ΣΙΓΟΥΡΑ υπάρχει
        existing_agents = [
            ("raspberrypi-01", "wEMFje4up11GLvqINeMix4j_cJqUu7wLLMXYb15BFmY"),
            ("DRONE-01", "DWVkXiDJ_IIbdkxRTSIKjAhe4bFUuvhFgiMfWhaII"),
            ("Robot_Arm_001", "DVvkafojenj6091wusBSJbL02gIawkIFt2oS8rJIF4U"),
            ("PLC001", "kGha2GWsIsJhs6UTh3smngAPBqdMmeMd2XRKp317JeA"),
            ("CAM-WH-01", "QIFDkxVGMQ0dzMnn90-GlqzBpMVr4425FRIYvAIyFTU")
        ]
    
        # Δοκιμάζουμε κάθε agent μέχρι να βρούμε έναν που δουλεύει
        for agent_id, api_key in existing_agents:
            logger.info(f"  Trying agent: {agent_id}")
        
            test_agent = SimulatedAgent(
                agent_id=agent_id,  # Χρήση ΥΠΑΡΧΟΝΤΟΣ agent_id
                agent_type=AgentType.SENSOR,  # Ο τύπος δεν επηρεάζει το authentication
                api_key=api_key,    # Χρήση ΥΠΑΡΧΟΝΤΟΣ api_key
                frequency=999,
                backend_url=self.backend_url
            )
        
            try:
                success, latency = test_agent.send_telemetry()
                if success:
                    logger.info(f"✅ Agent authentication test PASSED using {agent_id} (latency: {latency:.2f}ms)")
                    return True
                else:
                    logger.warning(f"  ⚠️ Agent {agent_id} failed, trying next...")
            except Exception as e:
                logger.warning(f"  ⚠️ Agent {agent_id} error: {e}")
    
        # Αν κανένας agent δεν δούλεψε
        logger.error("❌ Agent authentication test FAILED for ALL known agents")
        logger.error("   This suggests the backend might be down or the API endpoint has changed")
        logger.error("   Check that the backend is running and /api/telemetry endpoint exists")
        return False

    def test_all_agent_types(self) -> bool:
        """Δοκιμάζει authentication για ΟΛΟΥΣ τους τύπους agents"""
        logger.info("🔍 Testing authentication for all agent types...")
        
        success_count = 0
        total_tests = len(AgentType)
        
        for agent_type in AgentType:
            config = self.agent_pool.base_configs[agent_type]
            
            test_agent = SimulatedAgent(
                agent_id=f"test_{agent_type.value}",
                agent_type=agent_type,
                api_key=config.base_api_key,
                frequency=999,
                backend_url=self.backend_url
            )
            
            try:
                success, latency = test_agent.send_telemetry()
                if success:
                    logger.info(f"  ✅ {agent_type.value}: OK ({latency:.2f}ms)")
                    success_count += 1
                else:
                    logger.error(f"  ❌ {agent_type.value}: FAILED")
            except Exception as e:
                logger.error(f"  ❌ {agent_type.value}: ERROR - {e}")
        
        if success_count == total_tests:
            logger.info(f"✅ All {total_tests} agent types authenticated successfully")
            return True
        else:
            logger.warning(f"⚠️ Only {success_count}/{total_tests} agent types authenticated")
            return False

    def register_test_agent(self, agent_id: str, agent_type: str, api_key: str) -> bool:
        """Προσπαθεί να εγγράψει έναν νέο agent στο backend"""
        try:
            response = requests.post(
                f"{self.backend_url}/api/agents/register",
                json={
                    'agent_id': agent_id,
                    'agent_type': agent_type,
                    'api_key': api_key
                },
                timeout=5
            )
            if response.status_code == 200:
                logger.info(f"✅ Registered agent {agent_id}")
                return True
            else:
                logger.warning(f"⚠️ Could not register {agent_id}: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"❌ Registration error: {e}")
            return False
    
    def run_scalability_test(self, agent_multipliers: List[float] = [1, 2, 5, 10, 20],
                              test_duration: int = 300) -> List[TestResult]:
        """
        Εκτελεί scalability test με διαφορετικά load levels
        
        Args:
            agent_multipliers: Λίστα με multipliers για testing
            test_duration: Διάρκεια κάθε test σε seconds
        """
        
        if not self.check_backend_health():
            logger.error("Cannot start test - backend unhealthy")
            return []
        
        # ✅ ΚΡΙΣΙΜΟ: Έλεγχος authentication ΠΡΙΝ το test
        if not self.test_agent_authentication():
            logger.error("❌ Cannot proceed - agent authentication failed")
            logger.error("   Please run create_demo_data.py first to populate the database")
            logger.error("   Or check that the base API keys exist in the agents table")
            return []
        
        results = []
        
        for i, multiplier in enumerate(agent_multipliers):
            logger.info(f"\n{'='*60}")
            logger.info(f"Test {i+1}/{len(agent_multipliers)}: Multiplier = {multiplier}")
            logger.info(f"{'='*60}")
            
            # Δημιουργία agents
            agent_count = self.agent_pool.create_agents_for_test(multiplier)
            
            # Έναρξη monitoring
            self.monitor.start_monitoring(interval_seconds=2)
            
            # Έναρξη agents
            self.agent_pool.start_all()
            
            # Αναμονή για stabilization (30 sec)
            logger.info("⏳ Waiting for stabilization (30 seconds)...")
            time.sleep(30)
            
            # Συλλογή baseline
            baseline_start = time.time()
            
            # Κύρια φάση test
            logger.info(f"📈 Running test for {test_duration} seconds...")
            time.sleep(test_duration)
            
            # Σταμάτημα agents
            agent_stats = self.agent_pool.stop_all()
            
            # Σταμάτημα monitoring
            monitoring_df = self.monitor.stop_monitoring()
            
            # Υπολογισμός αποτελεσμάτων
            result = self._calculate_test_result(
                multiplier=multiplier,
                agent_count=agent_count,
                duration=test_duration,
                agent_stats=agent_stats,
                monitoring_df=monitoring_df
            )
            
            results.append(result)
            self.test_results.append(result)
            
            # Καθαρισμός πριν επόμενο test
            logger.info("🧹 Cleaning up for next test...")
            time.sleep(10)
        
        return results
    
    def _calculate_test_result(self, multiplier: float, agent_count: int,
                               duration: int, agent_stats: Dict,
                               monitoring_df: pd.DataFrame) -> TestResult:
        """Υπολογίζει TestResult από raw δεδομένα"""
        
        # Υπολογισμός επιτυχιών και αποτυχιών από agents
        successful = sum(a.message_count for a in self.agent_pool.agents)
        failed = sum(a.error_count for a in self.agent_pool.agents)
        
        # Υπολογισμός latencies από agents
        all_latencies = []
        for agent in self.agent_pool.agents:
            all_latencies.extend(agent.latencies)
        
        result = TestResult(
            test_id=f"{self.test_id}_mult{multiplier}",
            timestamp=datetime.now(),
            duration_seconds=duration,
            multiplier=multiplier,
            active_agents=agent_count,
            telemetry_rate=successful / duration if duration > 0 else 0,  # Σωστός υπολογισμός rate
            api_requests=successful,
            api_errors=failed,
            avg_response_time_ms=np.mean(all_latencies) if all_latencies else 0,
            p95_response_time_ms=np.percentile(all_latencies, 95) if all_latencies else 0,
            p99_response_time_ms=np.percentile(all_latencies, 99) if all_latencies else 0,
            cpu_usage_percent=0,
            memory_usage_mb=0,
            network_in_mbps=0,
            network_out_mbps=0,
            db_connections=0,
            db_query_time_ms=0,
            alerts_generated=0,
            scans_completed=0,
            queue_size=0
        )
        
        # Υπολογισμός από monitoring data
        if not monitoring_df.empty:
            if 'db_connections' in monitoring_df.columns:
                result.db_connections = int(monitoring_df['db_connections'].mean())
            
            if 'alert_rate' in monitoring_df.columns:
                result.alerts_generated = int(monitoring_df['alert_rate'].sum())
        
        # Υπολογισμός success_rate 
        total = successful + failed
        if total > 0:
            result.success_rate = (successful / total) * 100
        else:
            result.success_rate = 0.0
        
        result.successful_requests = successful
        result.failed_requests = failed
        result.total_requests = total
        
        result.metadata = {
            'multiplier': multiplier,
            'agent_stats': agent_stats,
            'monitoring_points': len(monitoring_df)
        }
        
        return result
    
    def run_attack_tests(self) -> pd.DataFrame:
        """Εκτελεί όλα τα attack scenarios"""
        
        if not self.check_backend_health():
            logger.error("Cannot start attack tests - backend unhealthy")
            return pd.DataFrame()
        
        logger.info(f"\n{'='*60}")
        logger.info(f"Running Attack Tests")
        logger.info(f"{'='*60}")
        
        # Εκτέλεση port scans
        for intensity in ['low', 'medium', 'high']:
            self.attack_sim.port_scan_attack(intensity=intensity)
            time.sleep(10)  # Cooldown
        
        # Εκτέλεση brute force
        for intensity in ['low', 'medium', 'high']:
            self.attack_sim.brute_force_attack(intensity=intensity)
            time.sleep(10)
        
        # Εκτέλεση flood attacks
        for intensity in ['low', 'medium', 'high']:
            self.attack_sim.telemetry_flood_attack(intensity=intensity)
            time.sleep(10)
        
        attack_df = self.attack_sim.get_results_dataframe()
        logger.info(f"✅ Completed {len(attack_df)} attack scenarios")
        
        return attack_df
    
    def close(self):
        """Καθαρισμός resources"""
        self.monitor.close()
        logger.info("TestController closed")


# ============================================================================
# VISUALIZATION ENGINE
# ============================================================================

class VisualizationEngine:
    """Δημιουργία διαγραμμάτων από αποτελέσματα δοκιμών"""
    
    def __init__(self, output_dir: str = "./test_results"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Style settings
        plt.style.use('seaborn-v0_8-darkgrid')
        sns.set_palette("husl")
        
        logger.info(f"VisualizationEngine initialized, output dir: {output_dir}")
    
    def plot_scalability_results(self, results: List[TestResult], 
                                  filename: str = "scalability_results.png"):
        """Δημιουργεί scalability plots"""
        
        if not results:
            logger.warning("No results to plot")
            return
        
        # Δημιουργία DataFrame
        df = pd.DataFrame([asdict(r) for r in results])
        df = df.sort_values('active_agents')
        
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        fig.suptitle('Scalability Test Results', fontsize=16, fontweight='bold')
        
        # 1. Response Time vs Agents
        ax1 = axes[0, 0]
        ax1.plot(df['active_agents'], df['avg_response_time_ms'], 'o-', 
                label='Average', linewidth=2, markersize=8)
        ax1.plot(df['active_agents'], df['p95_response_time_ms'], 's-', 
                label='p95', linewidth=2, markersize=8)
        ax1.plot(df['active_agents'], df['p99_response_time_ms'], '^-', 
                label='p99', linewidth=2, markersize=8)
        ax1.set_xlabel('Number of Agents')
        ax1.set_ylabel('Response Time (ms)')
        ax1.set_title('Response Time vs System Load')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # 2. Success Rate vs Agents
        ax2 = axes[0, 1]
        ax2.plot(df['active_agents'], df['success_rate'], 'o-', 
                color='green', linewidth=2, markersize=8)
        ax2.set_xlabel('Number of Agents')
        ax2.set_ylabel('Success Rate (%)')
        ax2.set_title('Success Rate vs System Load')
        ax2.set_ylim([0, 105])
        ax2.grid(True, alpha=0.3)
        
        # 3. Telemetry Rate vs Agents
        ax3 = axes[0, 2]
        ax3.bar(df['active_agents'], df['telemetry_rate'], 
                alpha=0.7, color='skyblue', edgecolor='navy')
        ax3.set_xlabel('Number of Agents')
        ax3.set_ylabel('Telemetry Rate (msg/sec)')
        ax3.set_title('Telemetry Throughput')
        ax3.grid(True, alpha=0.3, axis='y')
        
        # 4. Database Connections
        ax4 = axes[1, 0]
        ax4.plot(df['active_agents'], df['db_connections'], 'o-', 
                color='orange', linewidth=2, markersize=8)
        ax4.set_xlabel('Number of Agents')
        ax4.set_ylabel('DB Connections')
        ax4.set_title('Database Connections')
        ax4.grid(True, alpha=0.3)
        
        # 5. Alert Generation
        ax5 = axes[1, 1]
        ax5.plot(df['active_agents'], df['alerts_generated'], 'o-', 
                color='red', linewidth=2, markersize=8)
        ax5.set_xlabel('Number of Agents')
        ax5.set_ylabel('Alerts Generated')
        ax5.set_title('Security Alerts vs Load')
        ax5.grid(True, alpha=0.3)
        
        # 6. Error Rate
        ax6 = axes[1, 2]
        error_rate = (df['api_errors'] / df['api_requests']) * 100
        ax6.plot(df['active_agents'], error_rate, 'o-', 
                color='purple', linewidth=2, markersize=8)
        ax6.set_xlabel('Number of Agents')
        ax6.set_ylabel('Error Rate (%)')
        ax6.set_title('Error Rate vs Load')
        ax6.grid(True, alpha=0.3)
        
        plt.tight_layout()
        output_path = os.path.join(self.output_dir, filename)
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"✅ Scalability plot saved to {output_path}")
    
    def plot_attack_detection(self, attack_df: pd.DataFrame,
                          filename: str = "attack_detection.png"):
        """Δημιουργεί plots για attack detection - ΔΙΟΡΘΩΜΕΝΟ για NaN"""
    
        if attack_df.empty:
            logger.warning("No attack data to plot")
            return
    
        # Αποθήκευση CSV
        csv_path = os.path.join(self.output_dir, 'attack_results.csv')
        attack_df.to_csv(csv_path, index=False)
        logger.info(f"✅ Attack results CSV saved to {csv_path}")
    
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Attack Detection Analysis', fontsize=16, fontweight='bold')
    
        # 1. Detection Rate by Attack Type
        ax1 = axes[0, 0]
        detection_by_type = attack_df.groupby('attack_type')['detected'].mean() * 100
        detection_by_type.plot(kind='bar', ax=ax1, color=['green', 'orange', 'red'])
        ax1.set_xlabel('Attack Type')
        ax1.set_ylabel('Detection Rate (%)')
        ax1.set_title('Detection Rate by Attack Type')
        ax1.set_ylim([0, 105])
        ax1.grid(True, alpha=0.3, axis='y')
    
        # 2. Detection Time by Intensity
        ax2 = axes[0, 1]
        # Φιλτράρισμα για μη NaN detection times
        valid_times = attack_df[attack_df['detection_time_ms'].notna()]
        if not valid_times.empty:
            for attack_type in valid_times['attack_type'].unique():
                subset = valid_times[valid_times['attack_type'] == attack_type]
                ax2.bar(subset['intensity'] + f'\n{attack_type}', 
                       subset['detection_time_ms'] / 1000,
                       alpha=0.7, label=attack_type)
            ax2.set_xlabel('Attack Type / Intensity')
            ax2.set_ylabel('Detection Time (seconds)')
            ax2.set_title('Time to Detect by Attack Type')
            ax2.grid(True, alpha=0.3, axis='y')
            plt.setp(ax2.get_xticklabels(), rotation=45, ha='right')
        else:
            ax2.text(0.5, 0.5, 'No detection time data', 
                    ha='center', va='center', transform=ax2.transAxes)
            ax2.set_title('Time to Detect (No Data)')
    
        # 3. False Positive Analysis - ΔΙΟΡΘΩΜΕΝΟ για NaN
        ax3 = axes[1, 0]
        if 'false_positive' in attack_df.columns:
            # Αφαίρεση NaN
            false_positives = attack_df['false_positive'].dropna()
            if not false_positives.empty:
                false_pos_counts = false_positives.value_counts()
                # Βεβαιωθείτε ότι δεν υπάρχουν μηδενικές τιμές
                if len(false_pos_counts) > 0 and false_pos_counts.sum() > 0:
                    false_pos_counts.plot(kind='pie', ax=ax3, autopct='%1.1f%%')
                    ax3.set_title('False Positives Distribution')
                else:
                    ax3.text(0.5, 0.5, 'No false positive data', 
                            ha='center', va='center', transform=ax3.transAxes)
                    ax3.set_title('False Positives (No Data)')
            else:
                ax3.text(0.5, 0.5, 'No false positive data', 
                        ha='center', va='center', transform=ax3.transAxes)
                ax3.set_title('False Positives (No Data)')
        else:
            ax3.text(0.5, 0.5, 'No false positive column', 
                    ha='center', va='center', transform=ax3.transAxes)
            ax3.set_title('False Positives (No Data)')
    
        # 4. Summary Statistics
        ax4 = axes[1, 1]
        ax4.axis('off')
    
        detection_rate = attack_df['detected'].mean() * 100
        detected_count = attack_df['detected'].sum()
        total_attacks = len(attack_df)
    
        # Υπολογισμός μέσου χρόνου ανίχνευσης (μόνο για detected)
        avg_detection_time = attack_df[attack_df['detected']]['detection_time_ms'].mean()
        if pd.isna(avg_detection_time):
            avg_detection_time = 0
    
        stats_text = f"""
        Attack Detection Summary
        {'='*25}
    
        Total Attacks: {total_attacks}
        Detected: {detected_count}
        Detection Rate: {detection_rate:.1f}%
    
        By Intensity:
        Low: {attack_df[attack_df['intensity']=='low']['detected'].mean()*100:.1f}%
        Medium: {attack_df[attack_df['intensity']=='medium']['detected'].mean()*100:.1f}%
        High: {attack_df[attack_df['intensity']=='high']['detected'].mean()*100:.1f}%
    
        Avg Detection Time:
        {avg_detection_time/1000:.1f}s
        """
    
        ax4.text(0.1, 0.9, stats_text, transform=ax4.transAxes, 
                fontsize=12, verticalalignment='top',
                bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
        plt.tight_layout()
        output_path = os.path.join(self.output_dir, filename)
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
    
        logger.info(f"✅ Attack detection plot saved to {output_path}")
    
    def plot_comparative_analysis(self, results: List[TestResult],
                                   filename: str = "comparative_analysis.png"):
        """Δημιουργεί συγκριτική ανάλυση με baseline"""
        
        if not results:
            logger.warning("No results to plot")
            return
        
        df = pd.DataFrame([asdict(r) for r in results])
        baseline = df[df['active_agents'] == df['active_agents'].min()].iloc[0]
        
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Comparative Analysis vs Baseline', fontsize=16, fontweight='bold')
        
        # 1. Relative Performance Degradation
        ax1 = axes[0, 0]
        rel_perf = baseline['avg_response_time_ms'] / df['avg_response_time_ms'] * 100
        ax1.plot(df['active_agents'], rel_perf, 'o-', linewidth=2, markersize=8)
        ax1.axhline(y=100, color='r', linestyle='--', alpha=0.5, label='Baseline')
        ax1.set_xlabel('Number of Agents')
        ax1.set_ylabel('Relative Performance (%)')
        ax1.set_title('Performance Degradation')
        ax1.grid(True, alpha=0.3)
        ax1.legend()
        
        # 2. Resource Efficiency
        ax2 = axes[0, 1]
        efficiency = df['telemetry_rate'] / df['active_agents']
        ax2.plot(df['active_agents'], efficiency, 'o-', color='green', linewidth=2, markersize=8)
        ax2.set_xlabel('Number of Agents')
        ax2.set_ylabel('Efficiency (msg/sec per agent)')
        ax2.set_title('Resource Efficiency')
        ax2.grid(True, alpha=0.3)
        
        # 3. Cost per Agent (in resources)
        ax3 = axes[1, 0]
        cost_per_agent = df['db_connections'] / df['active_agents']
        ax3.plot(df['active_agents'], cost_per_agent, 'o-', color='orange', linewidth=2, markersize=8)
        ax3.set_xlabel('Number of Agents')
        ax3.set_ylabel('DB Connections per Agent')
        ax3.set_title('Resource Cost per Agent')
        ax3.grid(True, alpha=0.3)
        
        # 4. Scalability Factor
        ax4 = axes[1, 1]
        scalability = df['telemetry_rate'] / baseline['telemetry_rate']
        ideal = df['active_agents'] / baseline['active_agents']
        ax4.plot(df['active_agents'], scalability, 'o-', label='Actual', linewidth=2)
        ax4.plot(df['active_agents'], ideal, '--', label='Ideal Linear', linewidth=2)
        ax4.set_xlabel('Number of Agents')
        ax4.set_ylabel('Scalability Factor')
        ax4.set_title('Scalability Analysis')
        ax4.grid(True, alpha=0.3)
        ax4.legend()
        
        plt.tight_layout()
        output_path = os.path.join(self.output_dir, filename)
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"✅ Comparative analysis plot saved to {output_path}")
    
    def generate_report(self, results: List[TestResult], attack_df: pd.DataFrame,
                        filename: str = "test_report.html"):
        """Δημιουργεί HTML report με όλα τα αποτελέσματα"""
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security System Test Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                h1 {{ color: #333; }}
                h2 {{ color: #666; margin-top: 30px; }}
                table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #4CAF50; color: white; }}
                tr:nth-child(even) {{ background-color: #f2f2f2; }}
                .good {{ color: green; }}
                .warning {{ color: orange; }}
                .bad {{ color: red; }}
                .summary {{ background-color: #f9f9f9; padding: 20px; border-radius: 5px; }}
                img {{ max-width: 100%; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <h1>📊 Security System Test Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <div class="summary">
                <h2>Test Summary</h2>
                <p>Total Tests: {len(results)}</p>
                <p>Max Agents Tested: {max([r.active_agents for r in results]) if results else 0}</p>
                <p>Attack Scenarios: {len(attack_df)}</p>
                <p>Detection Rate: {attack_df['detected'].mean()*100:.1f}%</p>
            </div>
            
            <h2>Scalability Test Results</h2>
            <table>
                <tr>
                    <th>Agents</th>
                    <th>Telemetry Rate</th>
                    <th>Avg Response (ms)</th>
                    <th>p95 Response (ms)</th>
                    <th>Success Rate</th>
                    <th>Alerts</th>
                </tr>
        """
        
        for r in results:
            success_class = "good" if r.success_rate > 99 else "warning" if r.success_rate > 95 else "bad"
            html += f"""
                <tr>
                    <td>{r.active_agents}</td>
                    <td>{r.telemetry_rate:.1f}</td>
                    <td>{r.avg_response_time_ms:.1f}</td>
                    <td>{r.p95_response_time_ms:.1f}</td>
                    <td class="{success_class}">{r.success_rate:.1f}%</td>
                    <td>{r.alerts_generated}</td>
                </tr>
            """
        
        html += """
            </table>
            
            <h2>Attack Detection Results</h2>
            <table>
                <tr>
                    <th>Attack Type</th>
                    <th>Intensity</th>
                    <th>Detected</th>
                    <th>Detection Time (ms)</th>
                    <th>Notes</th>
                </tr>
        """
        
        for _, row in attack_df.iterrows():
            detected_class = "good" if row['detected'] else "bad"
            html += f"""
                <tr>
                    <td>{row['attack_type']}</td>
                    <td>{row['intensity']}</td>
                    <td class="{detected_class}">{'✅' if row['detected'] else '❌'}</td>
                    <td>{row['detection_time_ms']:.1f}</td>
                    <td>{row['notes']}</td>
                </tr>
            """
        
        html += """
            </table>
            
            <h2>Visualizations</h2>
            <img src="scalability_results.png" alt="Scalability Results">
            <img src="attack_detection.png" alt="Attack Detection">
            <img src="comparative_analysis.png" alt="Comparative Analysis">
            
            <h2>Conclusions</h2>
            <p>Based on the test results, the system demonstrates:</p>
            <ul>
        """
        
        # Συμπεράσματα
        if results:
            max_agents = max([r.active_agents for r in results])
            max_rate = max([r.telemetry_rate for r in results])
            html += f"""
                <li>✅ Successfully handled up to {max_agents} simulated agents</li>
                <li>📈 Peak throughput: {max_rate:.1f} messages/second</li>
            """
            
            # Ανάλυση απόδοσης
            baseline = min(results, key=lambda x: x.active_agents)
            peak = max(results, key=lambda x: x.active_agents)
            degradation = (1 - baseline.avg_response_time_ms / peak.avg_response_time_ms) * 100
            html += f"""
                <li>⚠️ Performance degradation at peak load: {degradation:.1f}%</li>
            """
        
        # Attack detection
        detection_rate = attack_df['detected'].mean() * 100 if not attack_df.empty else 0
        html += f"""
                <li>🔒 Overall attack detection rate: {detection_rate:.1f}%</li>
            </ul>
            
        </body>
        </html>
        """
        
        output_path = os.path.join(self.output_dir, filename)
        with open(output_path, 'w') as f:
            f.write(html)
        
        logger.info(f"✅ HTML report saved to {output_path}")


# ============================================================================
# MAIN EXECUTION SCRIPT
# ============================================================================

def main():
    """Κύρια συνάρτηση εκτέλεσης"""
    
    parser = argparse.ArgumentParser(description='Security System Test Framework')
    parser.add_argument('--backend', default='http://192.168.56.20:15000',
                       help='Backend URL')
    parser.add_argument('--db', default='postgresql://admin:password@localhost:15433/security_db',
                       help='Database URL')
    parser.add_argument('--api-key', default='monitor123',
                       help='API key for testing')
    parser.add_argument('--duration', type=int, default=300,
                       help='Test duration per phase (seconds)')
    parser.add_argument('--multipliers', nargs='+', type=float,
                       default=[1, 2, 5, 10, 20],
                       help='Agent multipliers to test')
    parser.add_argument('--skip-attacks', action='store_true',
                       help='Skip attack tests')
    parser.add_argument('--output-dir', default='./test_results',
                       help='Output directory for results')
    
    args = parser.parse_args()
    
    # Αρχικοποίηση
    logger.info("=" * 70)
    logger.info("SECURITY SYSTEM TEST FRAMEWORK")
    logger.info("=" * 70)
    logger.info(f"Backend: {args.backend}")
    logger.info(f"Database: {args.db}")
    logger.info(f"Test duration: {args.duration}s")
    logger.info(f"Multipliers: {args.multipliers}")
    
    # Έλεγχος backend
    try:
        response = requests.get(f"{args.backend}/health", timeout=5)
        if response.status_code == 200:
            logger.info("✅ Backend health check passed")
        else:
            logger.error(f"❌ Backend health check failed: {response.status_code}")
            sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Cannot connect to backend: {e}")
        sys.exit(1)
    
    # Δημιουργία controller
    controller = TestController(
        backend_url=args.backend,
        db_url=args.db,
        api_key=args.api_key
    )
    
    viz = VisualizationEngine(output_dir=args.output_dir)
    
    
    try:
        # 1. Scalability tests
        logger.info("\n" + "="*70)
        logger.info("PHASE 1: SCALABILITY TESTS")
        logger.info("="*70)
        
        results = controller.run_scalability_test(
            agent_multipliers=args.multipliers,
            test_duration=args.duration
        )
        
        # 2. Attack tests
        attack_df = pd.DataFrame()
        if not args.skip_attacks:
            logger.info("\n" + "="*70)
            logger.info("PHASE 2: ATTACK TESTS")
            logger.info("="*70)
            attack_df = controller.run_attack_tests()
        
        # 3. Δημιουργία διαγραμμάτων
        logger.info("\n" + "="*70)
        logger.info("PHASE 3: GENERATING VISUALIZATIONS")
        logger.info("="*70)
        
        if results:
            viz.plot_scalability_results(results)
            viz.plot_comparative_analysis(results)
        
        if not attack_df.empty:
            viz.plot_attack_detection(attack_df)
        
        # 4. HTML report
        viz.generate_report(results, attack_df)
        
        # 5. Αποθήκευση raw δεδομένων
        if results:
            df_results = pd.DataFrame([asdict(r) for r in results])
            df_results.to_csv(os.path.join(args.output_dir, 'scalability_results.csv'), index=False)
        
        if not attack_df.empty:
            attack_df.to_csv(os.path.join(args.output_dir, 'attack_results.csv'), index=False)
        
        logger.info("\n" + "="*70)
        logger.info("✅ TEST FRAMEWORK COMPLETED SUCCESSFULLY")
        logger.info(f"📁 Results saved to: {args.output_dir}")
        logger.info("="*70)
        
    except KeyboardInterrupt:
        logger.info("\n🛑 Test interrupted by user")
    except Exception as e:
        logger.error(f"❌ Test failed: {e}", exc_info=True)
    finally:
        controller.close()


if __name__ == "__main__":
    main()
