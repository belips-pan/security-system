#!/usr/bin/env python3
"""
Security System - Unified Demo Data Creation
Creates sample security data directly in PostgreSQL with unified schema
"""

import psycopg2
import os
import json
import random
import secrets
import logging
import sys
import bcrypt
import hashlib
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


def hash_password(password):
    """Mirror models.py's User.set_password() - real bcrypt hashing instead
    of a non-functional placeholder string."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def hash_api_key(raw_key):
    """Mirror models.py's hash_api_key() - the users/agents api_key columns
    store only this SHA-256 lookup hash, never the raw key, so the app's
    require_api_key lookups keep working against rows this script inserts."""
    return hashlib.sha256(raw_key.encode('utf-8')).hexdigest()


def mask_key(key, visible=8):
    """Show only a short prefix of a secret so full keys don't end up in logs."""
    if not key:
        return ''
    return f"{key[:visible]}..." if len(key) > visible else key


def create_unified_postgresql_database(postgres_url):
    """Create unified PostgreSQL database with sample security data"""
    try:
        # Connect to PostgreSQL
        conn = psycopg2.connect(postgres_url)
        cursor = conn.cursor()

        logger.info("Creating unified PostgreSQL database structure...")

        # Insert demo users - passwords and API keys are generated fresh on
        # every run rather than hardcoded, and are only ever logged once
        # (in full) right here so whoever runs this script can capture them.
        logger.info("Adding demo users...")
        admin_password = secrets.token_urlsafe(12)
        operator_password = secrets.token_urlsafe(12)
        admin_api_key = secrets.token_urlsafe(32)
        operator_api_key = secrets.token_urlsafe(32)

        users = [
            ('admin', 'admin@security-system.com', hash_password(admin_password), 'administrator', True,
             datetime.now() - timedelta(days=30), datetime.now() - timedelta(hours=2), hash_api_key(admin_api_key)),
            ('security_operator', 'operator@security-system.com', hash_password(operator_password), 'operator', True,
             datetime.now() - timedelta(days=15), datetime.now() - timedelta(hours=1), hash_api_key(operator_api_key))
        ]

        cursor.executemany('''
            INSERT INTO users (username, email, password_hash, role, is_active, created_at, last_login, api_key)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (username) DO NOTHING
        ''', users)

        logger.info("🔑 Demo user credentials (shown once, store them now):")
        logger.info(f"   admin / {admin_password}  (api_key: {admin_api_key})")
        logger.info(f"   security_operator / {operator_password}  (api_key: {operator_api_key})")

        # Insert demo agents - API keys generated fresh, not hardcoded.
        logger.info("Adding demo security agents...")
        agent_keys = {
            'Robot_Arm_001': secrets.token_urlsafe(32),
            'DRONE-01': secrets.token_urlsafe(32),
            'CAM-WH-01': secrets.token_urlsafe(32),
            'raspberrypi-01': secrets.token_urlsafe(32),
            'PLC001': secrets.token_urlsafe(32),
            'container_scanner': secrets.token_urlsafe(32),
        }

        agents = [
            ('Robot_Arm_001', 'robot_agent', 'WMS_Zone_A_Picking', 'active',
             datetime.now() - timedelta(days=5), datetime.now() - timedelta(minutes=15), hash_api_key(agent_keys['Robot_Arm_001'])),
            ('DRONE-01', 'drone_agent', 'Outdoor_Yard_Zone_B', 'active',
             datetime.now() - timedelta(days=5), datetime.now() - timedelta(minutes=10), hash_api_key(agent_keys['DRONE-01'])),
            ('CAM-WH-01', 'camera_agent', 'Warehouse Zone A - Entrance', 'active',
             datetime.now() - timedelta(days=5), datetime.now() - timedelta(minutes=5), hash_api_key(agent_keys['CAM-WH-01'])),
            ('raspberrypi-01', 'iot_agent', 'Control Room', 'active',
             datetime.now() - timedelta(days=5), datetime.now() - timedelta(minutes=3), hash_api_key(agent_keys['raspberrypi-01'])),
            ('PLC001', 'plc_agent', 'Warehouse_Main_Line_1', 'active',
             datetime.now() - timedelta(days=5), datetime.now() - timedelta(minutes=1), hash_api_key(agent_keys['PLC001'])),
            ('container_scanner', 'security_scanner', 'Security VM', 'active',
             datetime.now() - timedelta(days=5), datetime.now(), hash_api_key(agent_keys['container_scanner']))
        ]

        cursor.executemany('''
            INSERT INTO agents (agent_id, agent_type, location, status, created_at, last_seen, api_key)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (agent_id) DO NOTHING
        ''', agents)

        logger.info("🔑 Demo agent API keys (shown once, store them now):")
        for agent_id, key in agent_keys.items():
            logger.info(f"   {agent_id}: {key}")

        # Insert demo telemetry data
        logger.info("Generating demo telemetry data...")
        telemetry_data = []

        # Get agent IDs from the database
        cursor.execute("SELECT id, agent_id, agent_type FROM agents")
        agent_mapping = {row[1]: row[0] for row in cursor.fetchall()}
        agent_types = {row[1]: row[2] for row in cursor.fetchall()}

        for agent_name, agent_db_id in agent_mapping.items():
            agent_type = agent_types.get(agent_name, 'unknown')
            for hour in range(24):  # Last 24 hours of data
                timestamp = datetime.now() - timedelta(hours=hour)

                # Generate security score based on agent type
                if agent_type == 'robot_agent':
                    security_score = random.randint(70, 95)
                elif agent_type == 'drone_agent':
                    security_score = random.randint(75, 98)
                elif agent_type == 'camera_agent':
                    security_score = random.randint(80, 97)
                elif agent_type == 'plc_agent':
                    security_score = random.randint(65, 92)
                elif agent_type == 'iot_agent':
                    security_score = random.randint(60, 90)
                else:
                    security_score = random.randint(70, 95)

                metrics = {
                    'cpu_usage_percent': random.randint(5, 95),
                    'memory_usage_percent': random.randint(10, 85),
                    'network_throughput_mbps': random.randint(100, 1000)
                }

                anomalies = []
                if random.random() < 0.1:  # 10% chance of anomalies
                    anomaly_types = ['suspicious_login_attempt', 'unusual_network_traffic',
                                     'high_resource_usage', 'connection_timeout']
                    selected_anomalies = random.sample(anomaly_types, random.randint(1, 2))
                    anomalies = selected_anomalies

                telemetry_data.append((
                    agent_db_id,
                    timestamp,
                    security_score,
                    json.dumps(metrics),
                    json.dumps(anomalies)
                ))

        cursor.executemany('''
            INSERT INTO telemetry (agent_id, timestamp, security_score, metrics, anomalies)
            VALUES (%s, %s, %s, %s, %s)
        ''', telemetry_data)

        # Create some sample alerts
        logger.info("Creating sample alerts...")
        alerts = [
            ('medium', 'High CPU usage detected on robot arm', datetime.now() - timedelta(hours=2), 'Robot_Arm_001', False),
            ('low', 'Drone connection unstable', datetime.now() - timedelta(minutes=45), 'DRONE-01', True),
            ('high', 'Unauthorized access attempt detected', datetime.now() - timedelta(hours=1), 'CAM-WH-01', False),
            ('low', 'IoT device memory usage high', datetime.now() - timedelta(minutes=30), 'raspberrypi-01', True)
        ]

        cursor.execute("SELECT id, agent_id FROM agents")
        agent_id_map = {row[1]: row[0] for row in cursor.fetchall()}

        # Τώρα χρησιμοποίησε τα σωστά IDs
        alerts_with_ids = []
        for severity, message, timestamp, agent_string, resolved in alerts:
            if agent_string in agent_id_map:
                alerts_with_ids.append((
                    severity,
                    message,
                    timestamp,
                    agent_id_map[agent_string],  # Αυτό είναι το integer ID!
                    resolved
                ))

        cursor.executemany('''
            INSERT INTO alerts (severity, message, timestamp, agent_id, resolved)
            VALUES (%s, %s, %s, %s, %s)
        ''', alerts_with_ids)

        conn.commit()

        # Verify data creation
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM agents")
        agent_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM telemetry")
        telemetry_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alerts")
        alert_count = cursor.fetchone()[0]

        cursor.close()
        conn.close()

        logger.info(f"✅ Demo database created successfully!")
        logger.info(f"📊 Statistics: {user_count} users, {agent_count} agents, {telemetry_count} telemetry records, {alert_count} alerts")
        return True

    except Exception as e:
        logger.error(f"❌ Error creating demo database: {e}")
        return False


def verify_database(postgres_url):
    """Verify data in PostgreSQL database"""
    logger.info("🔍 Verifying database contents...")

    try:
        conn = psycopg2.connect(postgres_url)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM users")
        users_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM agents")
        agents_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM telemetry")
        telemetry_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM alerts")
        alerts_count = cursor.fetchone()[0]

        cursor.execute("SELECT agent_id, agent_type, api_key FROM agents")
        agents = cursor.fetchall()

        logger.info(f"📋 Agents in database:")
        for agent in agents:
            # Only a short prefix of the key is logged - never the full secret.
            logger.info(f"   {agent[0]} ({agent[1]}): {mask_key(agent[2])}")

        cursor.close()
        conn.close()

        logger.info(f"PostgreSQL: {users_count} users, {agents_count} agents, {telemetry_count} telemetry, {alerts_count} alerts")

        if users_count > 0 and agents_count > 0:
            logger.info("✅ Database verification successful!")
            return True
        else:
            logger.warning("⚠️  Database created but data counts are low")
            return False

    except Exception as e:
        logger.error(f"PostgreSQL verification failed: {e}")
        return False


def main():
    """Main function"""
    logger.info("🚀 Starting Security System Unified Demo Data Setup...")

    # Χρησιμοποιήστε τη σωστή θύρα 15433 (όπως στο docker-compose)
    postgres_password = os.environ.get('POSTGRES_PASSWORD', 'password')
    POSTGRES_URL = f'postgresql://admin:{postgres_password}@localhost:15433/security_db'

    logger.info("Connecting to PostgreSQL at: postgresql://admin:***@localhost:15433/security_db")

    # Step 1: Create demo data directly in PostgreSQL
    if not create_unified_postgresql_database(POSTGRES_URL):
        logger.error("Failed to create demo PostgreSQL database")
        sys.exit(1)

    # Step 2: Verify database
    if not verify_database(POSTGRES_URL):
        logger.warning("Verification showed some issues")

    logger.info("🎉 Demo data setup completed successfully!")
    logger.info("💡 You can now run your security system with realistic data")
    logger.info("🔑 The demo user/agent credentials were printed once above - scroll up if you need them again.")


if __name__ == '__main__':
    main()
