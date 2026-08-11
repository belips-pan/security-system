#!/usr/bin/env python3
"""
Προσθέτει όλους τους simulated agents στη βάση δεδομένων
Εκτελέστε από το benchmarks directory με το backend σε λειτουργία
"""

import psycopg2
from psycopg2 import sql
import sys
from datetime import datetime

# Database connection - ΧΡΗΣΙΜΟΠΟΙΗΣΤΕ ΤΗ ΣΩΣΤΗ IP!
DB_URL = "postgresql://admin:password@192.168.56.20:15433/security_db"

# Base configurations (ίδια με το test_framework.py)
BASE_CONFIGS = {
    'camera': {
        'base_id': 'CAM-WH-01',
        'api_key': 'QIFDkxVGMQ0dzMnn90-GlqzBpMVr4425FRIYvAIyFTU',
        'type': 'camera_agent',
        'location': 'Warehouse Zone A',
        'count': 50
    },
    'drone': {
        'base_id': 'DRONE-01',
        'api_key': 'DWVkXiDJ_IIbdkxRTSIKjAhe4bFUuvhFgiMfWhaII',
        'type': 'drone_agent',
        'location': 'Outdoor Zone',
        'count': 10
    },
    'robot': {
        'base_id': 'Robot_Arm_001',
        'api_key': 'DVvkafojenj6091wusBSJbL02gIawkIFt2oS8rJIF4U',
        'type': 'robot_agent',
        'location': 'WMS_Zone_A',
        'count': 20
    },
    'sensor': {
        'base_id': 'raspberrypi-01',
        'api_key': 'wEMFje4up11GLvqINeMix4j_cJqUu7wLLMXYb15BFmY',
        'type': 'iot_agent',
        'location': 'Control Room',
        'count': 200
    },
    'plc': {
        'base_id': 'PLC001',
        'api_key': 'kGha2GWsIsJhs6UTh3smngAPBqdMmeMd2XRKp317JeA',
        'type': 'plc_agent',
        'location': 'Warehouse_Main_Line',
        'count': 30
    }
}

def test_connection():
    """Δοκιμάζει τη σύνδεση με τη βάση"""
    try:
        conn = psycopg2.connect(DB_URL)
        conn.close()
        print("✅ Επιτυχής σύνδεση με τη βάση δεδομένων")
        return True
    except Exception as e:
        print(f"❌ Αποτυχία σύνδεσης: {e}")
        return False

def add_test_agents():
    """Προσθέτει όλους τους test agents στη βάση"""
    
    conn = psycopg2.connect(DB_URL)
    cursor = conn.cursor()
    
    # Πρώτα, δείτε πόσοι υπάρχουν ήδη
    cursor.execute("SELECT COUNT(*) FROM agents")
    before = cursor.fetchone()[0]
    print(f"\n📊 Agents στη βάση ΠΡΙΝ: {before}")
    
    total_added = 0
    total_skipped = 0
    
    for agent_type, config in BASE_CONFIGS.items():
        print(f"\n📊 Προσθήκη {config['count']} {agent_type} agents...")
        
        for i in range(config['count']):
            # Δημιουργία agent_id με suffix
            if i == 0:
                agent_id = config['base_id']  # Το πρώτο κρατάει το original ID
            else:
                agent_id = f"{config['base_id']}_{i:03d}"
            
            # Έλεγχος αν υπάρχει ήδη
            cursor.execute("SELECT id FROM agents WHERE agent_id = %s", (agent_id,))
            if cursor.fetchone():
                total_skipped += 1
                if (i + 1) % 50 == 0:
                    print(f"  ⏭️  {agent_id} already exists")
                continue
            
            # Εισαγωγή νέου agent
            cursor.execute("""
                INSERT INTO agents 
                (agent_id, agent_type, location, status, api_key, created_at, last_seen)
                VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
            """, (
                agent_id,
                config['type'],
                f"{config['location']} - Test {i}",
                'active',
                config['api_key']  # ΟΛΟΙ οι clones έχουν το ίδιο API key!
            ))
            
            total_added += 1
            if (i + 1) % 20 == 0:
                print(f"  ✅ Added {i+1}/{config['count']} (latest: {agent_id})")
    
    conn.commit()
    
    # Τελικά στατιστικά
    cursor.execute("SELECT COUNT(*) FROM agents")
    after = cursor.fetchone()[0]
    
    cursor.execute("SELECT agent_type, COUNT(*) FROM agents GROUP BY agent_type ORDER BY agent_type")
    type_counts = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    print(f"\n{'='*50}")
    print(f"📊 ΑΠΟΤΕΛΕΣΜΑΤΑ:")
    print(f"{'='*50}")
    print(f"Agents ΠΡΙΝ: {before}")
    print(f"Agents ΜΕΤΑ: {after}")
    print(f"Προστέθηκαν: {total_added}")
    print(f"Υπήρχαν ήδη: {total_skipped}")
    print(f"\n📋 Ανά τύπο:")
    for agent_type, count in type_counts:
        print(f"  {agent_type:15s}: {count:3d}")
    
    return total_added

def verify_backend_compatibility():
    """Επαληθεύει ότι οι agents είναι συμβατοί με το backend"""
    conn = psycopg2.connect(DB_URL)
    cursor = conn.cursor()
    
    print(f"\n🔍 ΕΛΕΓΧΟΣ ΣΥΜΒΑΤΟΤΗΤΑΣ ΜΕ BACKEND:")
    print(f"{'='*50}")
    
    # Έλεγχος για duplicate agent_ids
    cursor.execute("""
        SELECT agent_id, COUNT(*) 
        FROM agents 
        GROUP BY agent_id 
        HAVING COUNT(*) > 1
    """)
    duplicates = cursor.fetchall()
    if duplicates:
        print(f"❌ Βρέθηκαν duplicates: {duplicates}")
    else:
        print(f"✅ Κανένα duplicate agent_id")
    
    # Έλεγχος για NULL api_keys
    cursor.execute("SELECT COUNT(*) FROM agents WHERE api_key IS NULL")
    null_keys = cursor.fetchone()[0]
    if null_keys > 0:
        print(f"⚠️  {null_keys} agents έχουν NULL api_key")
    else:
        print(f"✅ Όλοι οι agents έχουν API key")
    
    # Δείγμα agents
    cursor.execute("""
        SELECT agent_id, agent_type, api_key 
        FROM agents 
        ORDER BY agent_id 
        LIMIT 5
    """)
    samples = cursor.fetchall()
    print(f"\n📋 Δείγμα agents (πρώτοι 5):")
    for agent_id, agent_type, api_key in samples:
        print(f"  {agent_id:20s} | {agent_type:15s} | {api_key[:20]}...")
    
    cursor.close()
    conn.close()

def quick_test():
    """Γρήγορο test για επιβεβαίωση"""
    import requests
    import time
    
    print(f"\n🚀 ΓΡΗΓΟΡΟ TEST ΜΕ ΕΝΑΝ AGENT:")
    print(f"{'='*50}")
    
    # Δοκιμή με τον πρώτο camera agent
    test_agent = {
        'agent_id': 'CAM-WH-01_001',
        'api_key': 'QIFDkxVGMQ0dzMnn90-GlqzBpMVr4425FRIYvAIyFTU',
        'data': {
            'security_score': 95,
            'metrics': {'test': True},
            'anomalies': []
        }
    }
    
    headers = {
        'X-API-Key': test_agent['api_key'],
        'Content-Type': 'application/json'
    }
    
    telemetry = {
        'agent_id': test_agent['agent_id'],
        'timestamp': int(time.time()),
        'security_score': test_agent['data']['security_score'],
        'anomalies': test_agent['data']['anomalies'],
        'metrics': test_agent['data']['metrics']
    }
    
    try:
        response = requests.post(
            'http://192.168.56.20:15000/api/telemetry',
            json=telemetry,
            headers=headers,
            timeout=5
        )
        
        if response.status_code == 200:
            print(f"✅ ΕΠΙΤΥΧΙΑ! Agent {test_agent['agent_id']} έστειλε telemetry")
            print(f"   Response: {response.json()}")
        else:
            print(f"❌ ΑΠΟΤΥΧΙΑ! Status: {response.status_code}")
            print(f"   Response: {response.text}")
            
    except Exception as e:
        print(f"❌ ΣΦΑΛΜΑ: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("📦 ΠΡΟΣΘΗΚΗ TEST AGENTS ΣΤΗ ΒΑΣΗ")
    print("=" * 60)
    print(f"DB URL: {DB_URL}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Έλεγχος σύνδεσης
    if not test_connection():
        print("\n❌ Αδυναμία σύνδεσης στη βάση. Ελέγξτε:")
        print("   1. Το backend τρέχει;")
        print("   2. Η IP 192.168.56.20 είναι σωστή;")
        print("   3. Το port 15433 είναι ανοιχτό;")
        sys.exit(1)
    
    # Ερώτηση χρήστη
    print("\nΑυτό το script θα προσθέσει 310 test agents στη βάση.")
    print("ΔΕΝ θα επηρεάσει τους υπάρχοντες agents.")
    print("Το backend ΜΠΟΡΕΙ να είναι σε λειτουργία.")
    
    response = input("\n❓ Θέλετε να προσθέσετε τους test agents; (yes/no): ")
    if response.lower() in ['yes', 'y']:
        added = add_test_agents()
        verify_backend_compatibility()
        
        if added > 0:
            print(f"\n✅ Προστέθηκαν {added} νέοι agents!")
            response2 = input("\n❓ Θέλετε να κάνετε quick test; (yes/no): ")
            if response2.lower() in ['yes', 'y']:
                quick_test()
    else:
        print("⏭️  Ακύρωση")
    
    print("\n✅ Ολοκληρώθηκε!")
