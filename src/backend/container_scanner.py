# src/backend/container_scanner.py
import docker
import json
import os
import psycopg2
from datetime import datetime
import sys
import time
import subprocess

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

class ContainerSecurityScanner:
    def __init__(self):
        self.docker_client = None
        self.initialize_docker()
    
    def initialize_docker(self):
        """Initialize Docker client with fallback"""
        try:
            # Προσπάθεια 1: Χρήση Docker socket
            self.docker_client = docker.from_env()
            self.docker_client.ping()  # Test connection
            print("✅ Docker client initialized successfully (from_env)")
            return True
        except Exception as e:
            print(f"⚠️ Docker from_env failed: {e}")
            
            try:
                # Προσπάθεια 2: Χρήση TCP
                self.docker_client = docker.DockerClient(base_url='tcp://localhost:2375')
                self.docker_client.ping()
                print("✅ Docker client initialized successfully (TCP)")
                return True
            except Exception as e2:
                print(f"⚠️ Docker TCP failed: {e2}")
                
                # Προσπάθεια 3: Χρήση unix socket
                try:
                    self.docker_client = docker.DockerClient(base_url='unix://var/run/docker.sock')
                    self.docker_client.ping()
                    print("✅ Docker client initialized successfully (unix socket)")
                    return True
                except Exception as e3:
                    print(f"❌ All Docker connections failed: {e3}")
                    self.docker_client = None
                    return False
    
    def run_nmap_scan(self, target, scan_options="-sV -sC"):
        """Run nmap scan through container ή direct"""
        print(f"🔍 Starting nmap scan for {target} with options: {scan_options}")
        
        # Προσπάθεια 1: Χρήση Docker container
        if self.docker_client:
            try:
                return self._run_nmap_docker(target, scan_options)
            except Exception as docker_error:
                print(f"⚠️ Docker scan failed, trying direct nmap: {docker_error}")
                # Πτώση σε direct nmap
                return self._run_nmap_direct(target, scan_options)
        else:
            # Χρήση direct nmap αν δεν υπάρχει Docker
            return self._run_nmap_direct(target, scan_options)
    
    def _run_nmap_docker(self, target, scan_options):
        """Run nmap μέσω Docker container"""
        try:
            print(f"🐳 Running nmap via Docker container")
            
            # Έλεγχος αν υπάρχει η εικόνα
            try:
                self.docker_client.images.get("instrumentisto/nmap")
                print("✅ Nmap image already exists")
            except docker.errors.ImageNotFound:
                print("📥 Pulling nmap image...")
                self.docker_client.images.pull("instrumentisto/nmap")
                print("✅ Nmap image pulled")
            
            # Run scan
            container = self.docker_client.containers.run(
                "instrumentisto/nmap",
                f"{scan_options} {target}",
                remove=True,
                stdout=True,
                stderr=True,
                detach=False
            )
            
            output = container.decode('utf-8') if isinstance(container, bytes) else container
            
            print(f"✅ Nmap scan completed via Docker")
            
            return self._process_nmap_results(output, target, scan_options, 'docker')
            
        except docker.errors.ContainerError as e:
            error_msg = f"Docker container error: {e.stderr.decode('utf-8') if e.stderr else str(e)}"
            print(f"❌ Docker nmap failed: {error_msg}")
            return {
                'success': False,
                'error': error_msg,
                'tool': 'nmap',
                'target': target,
                'scan_options': scan_options,
                'timestamp': datetime.utcnow().isoformat(),
                'method': 'docker'
            }
        except Exception as e:
            error_msg = f"Docker unexpected error: {str(e)}"
            print(f"❌ Docker nmap failed: {error_msg}")
            return {
                'success': False,
                'error': error_msg,
                'tool': 'nmap',
                'target': target,
                'scan_options': scan_options,
                'timestamp': datetime.utcnow().isoformat(),
                'method': 'docker'
            }
    
    def _run_nmap_direct(self, target, scan_options):
        """Run nmap directly χωρίς Docker"""
        try:
            print(f"⚡ Running nmap directly (no Docker)")
            
            # Ελέγχουμε αν το nmap είναι εγκατεστημένο
            result = subprocess.run(
                ["which", "nmap"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                return {
                    'success': False,
                    'error': 'nmap not installed on system',
                    'tool': 'nmap',
                    'target': target,
                    'scan_options': scan_options,
                    'timestamp': datetime.utcnow().isoformat(),
                    'method': 'direct'
                }
            
            # Εκτέλεση nmap
            cmd = f"nmap {scan_options} {target}"
            print(f"   Command: {cmd}")
            
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            try:
                stdout, stderr = process.communicate(timeout=180)  # 3 λεπτά timeout
                
                if process.returncode == 0:
                    print(f"✅ Direct nmap completed successfully")
                    return self._process_nmap_results(stdout, target, scan_options, 'direct')
                else:
                    error_msg = f"nmap failed with code {process.returncode}: {stderr[:200]}"
                    print(f"❌ Direct nmap failed: {error_msg}")
                    return {
                        'success': False,
                        'error': error_msg,
                        'tool': 'nmap',
                        'target': target,
                        'scan_options': scan_options,
                        'timestamp': datetime.utcnow().isoformat(),
                        'method': 'direct',
                        'output': stdout[:500] if stdout else None,
                        'stderr': stderr[:500] if stderr else None
                    }
                    
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                error_msg = "nmap scan timed out after 3 minutes"
                print(f"❌ {error_msg}")
                return {
                    'success': False,
                    'error': error_msg,
                    'tool': 'nmap',
                    'target': target,
                    'scan_options': scan_options,
                    'timestamp': datetime.utcnow().isoformat(),
                    'method': 'direct'
                }
                
        except Exception as e:
            error_msg = f"Direct nmap failed: {str(e)}"
            print(f"❌ {error_msg}")
            return {
                'success': False,
                'error': error_msg,
                'tool': 'nmap',
                'target': target,
                'scan_options': scan_options,
                'timestamp': datetime.utcnow().isoformat(),
                'method': 'direct'
            }
    
    def _process_nmap_results(self, output, target, scan_options, method):
        """Process nmap results and extract information"""
        try:
            vulnerabilities = []
            open_ports = []
            services = []
            
            lines = output.split('\n')
            for line in lines:
                line_lower = line.lower()
                
                # Εύρεση ανοιχτών θυρών
                if '/tcp' in line and 'open' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port_info = parts[0]  # π.χ. "80/tcp"
                        state = parts[1]      # π.χ. "open"
                        service = parts[2] if len(parts) > 2 else "unknown"
                        
                        open_ports.append({
                            'port': port_info,
                            'state': state,
                            'service': service
                        })
                
                # Αναγνώριση πιθανών vulnerabilities
                if any(keyword in line_lower for keyword in ['vulnerable', 'weak', 'outdated', 'insecure']):
                    vulnerabilities.append(line.strip())
            
            # Εξαγωγή πληροφοριών
            host_info = "Unknown"
            for line in lines:
                if "Nmap scan report for" in line:
                    host_info = line.replace("Nmap scan report for", "").strip()
                    break
            
            result = {
                'success': True,
                'output': output,
                'tool': 'nmap',
                'target': target,
                'scan_options': scan_options,
                'timestamp': datetime.utcnow().isoformat(),
                'method': method,
                'parsed_results': {
                    'host': host_info,
                    'open_ports_count': len(open_ports),
                    'open_ports': open_ports,
                    'vulnerabilities_found': len(vulnerabilities),
                    'vulnerabilities': vulnerabilities,
                    'raw_output_preview': output[:1000] + "..." if len(output) > 1000 else output
                },
                'vulnerabilities_found': len(vulnerabilities)
            }
            
            print(f"   Found {len(open_ports)} open ports, {len(vulnerabilities)} potential vulnerabilities")
            return result
            
        except Exception as e:
            print(f"⚠️ Error processing nmap results: {e}")
            # Επιστροφή βασικών πληροφοριών ακόμα και αν η ανάλυση αποτύχει
            return {
                'success': True,
                'output': output,
                'tool': 'nmap',
                'target': target,
                'scan_options': scan_options,
                'timestamp': datetime.utcnow().isoformat(),
                'method': method,
                'vulnerabilities_found': 0,
                'parsed_results': {
                    'raw_output': output[:2000]
                }
            }
    
    def run_nuclei_scan(self, target, template_type="cves"):
        """Run nuclei scan through container"""
        print(f"🔍 Starting nuclei scan for {target} with templates: {template_type}")
        
        if not self.docker_client:
            return {
                'success': False,
                'error': 'Docker not available for nuclei scan',
                'tool': 'nuclei',
                'target': target,
                'template_type': template_type,
                'timestamp': datetime.utcnow().isoformat()
            }
        
        try:
            # Έλεγχος εικόνας
            try:
                self.docker_client.images.get("projectdiscovery/nuclei")
                print("✅ Nuclei image already exists")
            except docker.errors.ImageNotFound:
                print("📥 Pulling nuclei image...")
                self.docker_client.images.pull("projectdiscovery/nuclei")
                print("✅ Nuclei image pulled")
            
            # Run scan
            cmd = f"-u {target} -t {template_type} -silent -json"
            print(f"🐳 Running nuclei via Docker: {cmd}")
            
            container = self.docker_client.containers.run(
                "projectdiscovery/nuclei",
                cmd,
                remove=True,
                stdout=True,
                stderr=True,
                detach=False
            )
            
            output = container.decode('utf-8') if isinstance(container, bytes) else container
            
            print(f"✅ Nuclei scan completed")
            
            vulnerabilities = self._parse_nuclei_results(output)
            
            return {
                'success': True,
                'output': output,
                'tool': 'nuclei',
                'target': target,
                'template_type': template_type,
                'timestamp': datetime.utcnow().isoformat(),
                'vulnerabilities_found': len(vulnerabilities),
                'vulnerabilities': vulnerabilities,
                'parsed_results': {
                    'vulnerabilities_count': len(vulnerabilities),
                    'vulnerabilities': vulnerabilities[:10],  # Μόνο τα πρώτα 10
                    'raw_output_preview': output[:1000] + "..." if len(output) > 1000 else output
                }
            }
            
        except docker.errors.ContainerError as e:
            error_msg = f"Nuclei container error: {e.stderr.decode('utf-8') if e.stderr else str(e)}"
            print(f"❌ Nuclei scan failed: {error_msg}")
            return {
                'success': False,
                'error': error_msg,
                'tool': 'nuclei',
                'target': target,
                'template_type': template_type,
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception as e:
            error_msg = f"Nuclei scan failed: {str(e)}"
            print(f"❌ {error_msg}")
            return {
                'success': False,
                'error': error_msg,
                'tool': 'nuclei',
                'target': target,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _parse_nuclei_results(self, output):
        """Parse nuclei JSON results"""
        vulnerabilities = []
        try:
            lines = output.strip().split('\n')
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                try:
                    vuln = json.loads(line)
                    vulnerabilities.append({
                        'template': vuln.get('template-id', 'unknown'),
                        'name': vuln.get('info', {}).get('name', 'unknown'),
                        'severity': vuln.get('info', {}).get('severity', 'unknown'),
                        'description': vuln.get('info', {}).get('description', ''),
                        'host': vuln.get('host', 'unknown'),
                        'url': vuln.get('matched-at', '')
                    })
                except json.JSONDecodeError:
                    # Αν δεν είναι JSON, προσθέτουμε ως raw line
                    if 'http' in line.lower():
                        vulnerabilities.append({
                            'template': 'raw_output',
                            'name': 'Raw finding',
                            'severity': 'info',
                            'description': line,
                            'host': 'unknown',
                            'url': line[:200]
                        })
        except Exception as e:
            print(f"⚠️ Error parsing nuclei results: {e}")
        
        return vulnerabilities
    
    def test_scan_localhost(self):
        """Test function για έλεγχο scanner"""
        print("🧪 Testing scanner with localhost...")
        
        # Test nmap
        print("1. Testing nmap...")
        nmap_result = self.run_nmap_scan("localhost", "-sV")
        print(f"   Nmap success: {nmap_result.get('success')}")
        
        # Test nuclei (αν υπάρχει Docker)
        if self.docker_client:
            print("2. Testing nuclei...")
            nuclei_result = self.run_nuclei_scan("http://localhost", "cves")
            print(f"   Nuclei success: {nuclei_result.get('success')}")
        
        return {
            'nmap': nmap_result.get('success', False),
            'docker_available': self.docker_client is not None
        }

# Δημιουργία global instance
scanner = ContainerSecurityScanner()

# Test αν εκτελείται απευθείας
if __name__ == '__main__':
    print("=" * 80)
    print("🧪 CONTAINER SECURITY SCANNER TEST")
    print("=" * 80)
    
    result = scanner.test_scan_localhost()
    
    print("\n📊 TEST RESULTS:")
    print(f"   Docker available: {result['docker_available']}")
    print(f"   Nmap functional: {result['nmap']}")
    print(f"   Scanner ready: {result['nmap'] or result['docker_available']}")
    print("=" * 80)