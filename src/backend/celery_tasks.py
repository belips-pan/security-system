# /src/backend/celery_tasks.py
from celery import Celery
import json
from datetime import datetime
import psycopg2
import os
import sys
import time
import subprocess
import traceback

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Εισαγωγή ContainerSecurityScanner
try:
    from container_scanner import ContainerSecurityScanner
    SCANNER_AVAILABLE = True
    print("✅ ContainerSecurityScanner imported successfully")
    scanner = ContainerSecurityScanner()
except ImportError as e:
    print(f"⚠️ ContainerScanner not available: {e}")
    SCANNER_AVAILABLE = False
    scanner = None

# Χρησιμοποιούμε Redis σωστά
# Στο VM1 (Backend) μέσα στο Docker
REDIS_URL = 'redis://redis:6379/0' 
app = Celery('security_tasks', broker=REDIS_URL, backend=REDIS_URL)
# REDIS_URL = os.getenv('REDIS_URL', 'redis://redis:6379/0')


# Βασική configuration
app.conf.update(
    broker_url=REDIS_URL,
    result_backend=REDIS_URL,
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='Europe/Athens',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300,  # 5 minutes
    worker_concurrency=2,
    broker_connection_retry_on_startup=True,
    worker_send_task_events=True,
    task_send_sent_event=True,
    # Προσθήκη για καλύτερο Flower monitoring
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_annotations={
        '*': {'rate_limit': '10/m'}
    }
)

# Database connection
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://admin:password@postgres:5432/security_db')

# Προσθέτουμε αυτή τη συνάρτηση για ελέγχους:
@app.task(bind=True, name='flower_ping')
def flower_ping(self):
    """Task για να επιβεβαιώνει το Flower ότι οι workers είναι ενεργοί"""
    print("📡 Flower ping task executed")
    return {
        'status': 'pong',
        'worker': self.request.hostname,
        'timestamp': datetime.utcnow().isoformat(),
        'task_id': self.request.id
    }

# Celery Tasks
@app.task(bind=True, name='security_tasks.nmap_scan')
def nmap_scan_task(self, target, scan_options="-sV -sC"):
    """Celery task for nmap scanning - ΔΙΟΡΘΩΜΕΝΗ ΕΚΔΟΧΗ"""
    task_id = self.request.id
    start_time = time.time()
    
    print(f"🎯 [Task {task_id}] Starting nmap scan for {target} with options: {scan_options}")
    
    try:
        # Update task state for Flower monitoring
        self.update_state(
            state='PROGRESS',
            meta={
                'status': 'Initializing nmap scan...',
                'progress': 20,
                'current': 'Starting container',
                'total': 'Nmap scan',
                'target': target
            }
        )
        
        if not SCANNER_AVAILABLE or not scanner:
            error_msg = 'Scanner not available'
            print(f"❌ {error_msg}")
            
            result = {
                'success': False,
                'error': error_msg,
                'tool': 'nmap',
                'target': target,
                'scan_options': scan_options,
                'timestamp': datetime.utcnow().isoformat(),
                'duration_seconds': 0
            }
            
            # Try to save error
            try:
                save_scan_results(result)
            except:
                pass
            
            return result
        
        # Step 1: Pull image if needed
        self.update_state(
            state='PROGRESS',
            meta={
                'status': 'Checking Docker image...',
                'progress': 30,
                'current': 'Pulling nmap image',
                'total': 'Nmap scan'
            }
        )
        
        # Step 2: Run scan
        self.update_state(
            state='PROGRESS',
            meta={
                'status': 'Running nmap scan...',
                'progress': 50,
                'current': 'Executing nmap',
                'total': 'Nmap scan'
            }
        )
        
        results = scanner.run_nmap_scan(target, scan_options)
        
        # Step 3: Process results
        self.update_state(
            state='PROGRESS',
            meta={
                'status': 'Processing results...',
                'progress': 80,
                'current': 'Analyzing output',
                'total': 'Nmap scan'
            }
        )
        
        # Calculate duration
        duration = time.time() - start_time
        results['duration_seconds'] = round(duration, 2)
        results['task_id'] = task_id
        
        # Save results to database
        if results.get('success', False):
            try:
                save_scan_results(results)
                results['saved_to_db'] = True
                
                # Create alert if vulnerabilities found
                if results.get('vulnerabilities_found', 0) > 0:
                    create_alert(results)
            except Exception as e:
                print(f"⚠️ Could not save results to DB: {e}")
                results['saved_to_db'] = False
                results['db_error'] = str(e)
        
        print(f"✅ [Task {task_id}] Nmap scan completed for {target} in {duration:.2f}s")
        print(f"   Success: {results.get('success')}, Vulnerabilities: {results.get('vulnerabilities_found', 0)}")
        
        return results
        
    except Exception as e:
        error_msg = f"Nmap task failed: {str(e)}"
        print(f"❌ [Task {task_id}] {error_msg}")
        print(f"   Traceback: {traceback.format_exc()}")
        
        # Create error result
        error_result = {
            'success': False,
            'error': error_msg,
            'tool': 'nmap',
            'target': target,
            'scan_options': scan_options,
            'timestamp': datetime.utcnow().isoformat(),
            'duration_seconds': time.time() - start_time,
            'task_id': task_id
        }
        
        # Try to save error result
        try:
            save_scan_results(error_result)
        except Exception as save_error:
            print(f"⚠️ Could not save error result: {save_error}")
        
        return error_result

@app.task(bind=True, name='security_tasks.nuclei_scan')
def nuclei_scan_task(self, target, template_type="cves"):
    """Celery task for nuclei scanning - ΔΙΟΡΘΩΜΕΝΗ ΕΚΔΟΧΗ"""
    task_id = self.request.id
    start_time = time.time()
    
    print(f"🎯 [Task {task_id}] Starting nuclei scan for {target} with templates: {template_type}")
    
    try:
        # Update task state for Flower monitoring
        self.update_state(
            state='PROGRESS',
            meta={
                'status': 'Initializing nuclei scan...',
                'progress': 20,
                'current': 'Starting container',
                'total': 'Nuclei scan',
                'target': target
            }
        )
        
        if not SCANNER_AVAILABLE or not scanner:
            error_msg = 'Scanner not available'
            print(f"❌ {error_msg}")
            
            result = {
                'success': False,
                'error': error_msg,
                'tool': 'nuclei',
                'target': target,
                'template_type': template_type,
                'timestamp': datetime.utcnow().isoformat(),
                'duration_seconds': 0
            }
            
            return result
        
        # Run scan
        self.update_state(
            state='PROGRESS',
            meta={
                'status': 'Running nuclei scan...',
                'progress': 60,
                'current': 'Executing nuclei',
                'total': 'Nuclei scan'
            }
        )
        
        results = scanner.run_nuclei_scan(target, template_type)
        
        # Process results
        self.update_state(
            state='PROGRESS',
            meta={
                'status': 'Processing vulnerabilities...',
                'progress': 80,
                'current': 'Analyzing findings',
                'total': 'Nuclei scan'
            }
        )
        
        # Calculate duration
        duration = time.time() - start_time
        results['duration_seconds'] = round(duration, 2)
        results['task_id'] = task_id
        
        # Save results to database
        if results.get('success', False):
            try:
                save_scan_results(results)
                results['saved_to_db'] = True
                
                # Create alert if vulnerabilities found
                if results.get('vulnerabilities_found', 0) > 0:
                    create_alert(results)
            except Exception as e:
                print(f"⚠️ Could not save results to DB: {e}")
                results['saved_to_db'] = False
        
        print(f"✅ [Task {task_id}] Nuclei scan completed for {target} in {duration:.2f}s")
        print(f"   Success: {results.get('success')}, Vulnerabilities: {results.get('vulnerabilities_found', 0)}")
        
        return results
        
    except Exception as e:
        error_msg = f"Nuclei task failed: {str(e)}"
        print(f"❌ [Task {task_id}] {error_msg}")
        print(f"   Traceback: {traceback.format_exc()}")
        
        error_result = {
            'success': False,
            'error': error_msg,
            'tool': 'nuclei',
            'target': target,
            'template_type': template_type,
            'timestamp': datetime.utcnow().isoformat(),
            'duration_seconds': time.time() - start_time,
            'task_id': task_id
        }
        
        return error_result

@app.task(bind=True, name='security_tasks.comprehensive_scan')
def comprehensive_scan_task(self, target):
    """Run comprehensive security scan - both nmap and nuclei - ΔΙΟΡΘΩΜΕΝΗ"""
    task_id = self.request.id
    start_time = time.time()
    
    print(f"🎯 [Task {task_id}] Starting comprehensive scan for {target}")
    
    # Update progress
    self.update_state(
        state='PROGRESS',
        meta={
            'status': 'Starting comprehensive scan...',
            'progress': 10,
            'current': 'Initializing',
            'total': 'Comprehensive scan',
            'target': target
        }
    )
    
    try:
        # Run both scans sequentially (not parallel για απλότητα)
        self.update_state(
            state='PROGRESS',
            meta={
                'status': 'Running nmap scan...',
                'progress': 30,
                'current': 'Nmap',
                'total': 'Comprehensive scan'
            }
        )
        
        # Run nmap first
        nmap_result = scanner.run_nmap_scan(target, "-sV -sC")
        nmap_result['task_id'] = f"{task_id}_nmap"
        
        self.update_state(
            state='PROGRESS',
            meta={
                'status': 'Running nuclei scan...',
                'progress': 60,
                'current': 'Nuclei',
                'total': 'Comprehensive scan'
            }
        )
        
        # Then run nuclei
        nuclei_result = scanner.run_nuclei_scan(target, "cves")
        nuclei_result['task_id'] = f"{task_id}_nuclei"
        
        # Calculate duration
        duration = time.time() - start_time
        
        # Combine results
        combined_result = {
            'success': nmap_result.get('success', False) or nuclei_result.get('success', False),
            'nmap': nmap_result,
            'nuclei': nuclei_result,
            'target': target,
            'tool': 'comprehensive',
            'comprehensive_scan': True,
            'timestamp': datetime.utcnow().isoformat(),
            'duration_seconds': round(duration, 2),
            'task_id': task_id,
            'total_vulnerabilities_found': (
                nmap_result.get('vulnerabilities_found', 0) + 
                nuclei_result.get('vulnerabilities_found', 0)
            )
        }
        
        # Save combined results
        try:
            save_scan_results(combined_result)
            combined_result['saved_to_db'] = True
            
            # Create alert if vulnerabilities found
            if combined_result['total_vulnerabilities_found'] > 0:
                create_alert(combined_result)
        except Exception as e:
            print(f"⚠️ Could not save comprehensive results to DB: {e}")
            combined_result['saved_to_db'] = False
        
        print(f"✅ [Task {task_id}] Comprehensive scan completed for {target} in {duration:.2f}s")
        print(f"   Nmap success: {nmap_result.get('success')}")
        print(f"   Nuclei success: {nuclei_result.get('success')}")
        print(f"   Total vulnerabilities: {combined_result['total_vulnerabilities_found']}")
        
        return combined_result
        
    except Exception as e:
        error_msg = f"Comprehensive scan failed: {str(e)}"
        print(f"❌ [Task {task_id}] {error_msg}")
        print(f"   Traceback: {traceback.format_exc()}")
        
        return {
            'success': False,
            'error': str(e),
            'target': target,
            'comprehensive_scan': True,
            'timestamp': datetime.utcnow().isoformat(),
            'duration_seconds': time.time() - start_time,
            'task_id': task_id
        }

@app.task(bind=True, name='security_tasks.test_celery_worker')
def test_celery_worker(self):
    """Test task to verify Celery worker is running"""
    task_id = self.request.id
    print(f"🧪 [Task {task_id}] Running test Celery worker task")
    
    # Simulate some work for Flower monitoring
    for i in range(5):
        self.update_state(
            state='PROGRESS',
            meta={
                'status': f'Testing... Step {i+1}/5',
                'progress': (i+1) * 20,
                'current': f'Step {i+1}',
                'total': 'Test'
            }
        )
        time.sleep(0.5)
    
    return {
        'status': 'success',
        'message': 'Celery worker is operational',
        'worker': self.request.hostname,
        'timestamp': datetime.utcnow().isoformat(),
        'task_id': task_id
    }

@app.task(bind=True, name='security_tasks.quick_scan')
def quick_scan(self, target):
    """Quick security scan with basic options"""
    task_id = self.request.id
    print(f"⚡ [Task {task_id}] Quick scan for {target}")
    
    # Χρησιμοποιούμε την nmap task με βασικές επιλογές
    return nmap_scan_task.delay(target, "-sV --top-ports 100")

# Helper functions για database
def save_scan_results(scan_results):
    """Save scan results to PostgreSQL database"""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_scans (
                id SERIAL PRIMARY KEY,
                task_id VARCHAR(255),
                tool VARCHAR(50),
                target VARCHAR(255),
                results JSONB,
                success BOOLEAN,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute('''
            INSERT INTO security_scans 
            (task_id, tool, target, results, success, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (
            scan_results.get('task_id', 'unknown'),
            scan_results.get('tool', 'unknown'),
            scan_results.get('target', 'unknown'),
            json.dumps(scan_results),
            scan_results.get('success', False),
            datetime.utcnow()
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        print(f"✅ Scan results saved to database: {scan_results.get('tool')} on {scan_results.get('target')}")
        return True
        
    except Exception as e:
        print(f"❌ Error saving scan results to database: {e}")
        # Fallback to file
        try:
            scans_dir = '/app/scans_fallback'
            os.makedirs(scans_dir, exist_ok=True)
            
            filename = f"{scan_results.get('tool', 'unknown')}_{scan_results.get('target', 'unknown')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = os.path.join(scans_dir, filename)
            
            with open(filepath, 'w') as f:
                json.dump(scan_results, f, indent=2)
            
            print(f"⚠️ Results saved to JSON fallback: {filepath}")
            return True
        except Exception as file_error:
            print(f"❌ JSON fallback also failed: {file_error}")
            return False

def create_alert(scan_results):
    """Create alert in existing alerts table"""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        # Check if alerts table exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                severity VARCHAR(20),
                message TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                agent_id VARCHAR(100),
                resolved BOOLEAN DEFAULT FALSE
            )
        """)
        
        vulnerabilities_count = scan_results.get('vulnerabilities_found', 0)
        tool = scan_results.get('tool', 'unknown')
        target = scan_results.get('target', 'unknown')
        
        if vulnerabilities_count > 0:
            message = f"{tool} found {vulnerabilities_count} vulnerabilities on {target}"
            severity = 'high'
        else:
            message = f"{tool} completed scan on {target}"
            severity = 'info'
        
        cursor.execute('''
            INSERT INTO alerts 
            (severity, message, timestamp, agent_id, resolved)
            VALUES (%s, %s, %s, %s, %s)
        ''', (
            severity,
            message,
            datetime.utcnow(),
            'container_scanner',
            False
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
        print(f"✅ Alert created: {message}")
    except Exception as e:
        print(f"❌ Error creating alert: {e}")

# Simple direct nmap scan function για debugging
def direct_nmap_scan(target, options="-sV -sC"):
    """Direct nmap scan without Celery για testing"""
    try:
        print(f"🔍 Running direct nmap scan on {target}")
        result = subprocess.run(
            f"nmap {options} {target}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        output = result.stdout
        success = result.returncode == 0
        
        return {
            'success': success,
            'output': output,
            'error': result.stderr if not success else None,
            'tool': 'nmap',
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
            'vulnerabilities_found': 0,  # Βασική ανάλυση
            'raw_command': f"nmap {options} {target}"
        }
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'error': 'Nmap scan timed out after 30 seconds',
            'tool': 'nmap',
            'target': target,
            'timestamp': datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'tool': 'nmap',
            'target': target,
            'timestamp': datetime.utcnow().isoformat()
        }

if __name__ == '__main__':
    # Start Celery worker
    print("=" * 80)
    print("🚀 SECURITY SCANNER CELERY WORKER")
    print("=" * 80)
    print(f"📡 Broker: {REDIS_URL}")
    print(f"💾 Database: {DATABASE_URL}")
    print(f"🔧 Available tasks:")
    print(f"   - security_tasks.nmap_scan")
    print(f"   - security_tasks.nuclei_scan")
    print(f"   - security_tasks.comprehensive_scan")
    print(f"   - security_tasks.test_celery_worker")
    print(f"   - security_tasks.quick_scan")
    print("=" * 80)
    
    # Test scanner availability
    if SCANNER_AVAILABLE and scanner:
        print(f"✅ ContainerSecurityScanner: AVAILABLE")
        if scanner.docker_client:
            print(f"✅ Docker client: AVAILABLE")
        else:
            print(f"❌ Docker client: UNAVAILABLE")
    else:
        print(f"❌ ContainerSecurityScanner: UNAVAILABLE")
    
    app.start()