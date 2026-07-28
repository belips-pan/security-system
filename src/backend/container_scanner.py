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

from security_validation import validate_target, validate_nmap_options, validate_nuclei_template

# Bounded wait for scanner containers so a Celery hard-kill (or any other
# outer timeout) can never orphan a running scan container.
NMAP_CONTAINER_TIMEOUT_SECONDS = 280
NUCLEI_CONTAINER_TIMEOUT_SECONDS = 280


class ContainerSecurityScanner:
    def __init__(self):
        self.docker_client = None
        self.initialize_docker()

    def initialize_docker(self):
        """Initialize Docker client.

        docker.from_env() honours DOCKER_HOST/DOCKER_TLS_VERIFY/DOCKER_CERT_PATH,
        so this works both against a directly-mounted unix socket and against
        a docker-socket-proxy reachable over tcp:// (see docker-compose.yml).
        """
        try:
            self.docker_client = docker.from_env()
            self.docker_client.ping()  # Test connection
            print("✅ Docker client initialized successfully (from_env)")
            return True
        except Exception as e:
            print(f"⚠️ Docker from_env failed: {e}")

            # Fallback: explicit unix socket path, for environments where
            # DOCKER_HOST isn't set but the socket is bind-mounted directly.
            try:
                self.docker_client = docker.DockerClient(base_url='unix://var/run/docker.sock')
                self.docker_client.ping()
                print("✅ Docker client initialized successfully (unix socket)")
                return True
            except Exception as e2:
                print(f"❌ All Docker connections failed: {e2}")
                self.docker_client = None
                return False

    def run_nmap_scan(self, target, scan_options="-sV -sC"):
        """Run nmap scan through container ή direct"""
        print(f"🔍 Starting nmap scan for {target} with options: {scan_options}")

        if not validate_target(target):
            return self._invalid_input_result('nmap', target, scan_options, 'Invalid or unsafe target')
        if not validate_nmap_options(scan_options):
            return self._invalid_input_result('nmap', target, scan_options, 'Invalid or unsafe nmap options')

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

    def _invalid_input_result(self, tool, target, options, reason):
        print(f"❌ Rejecting {tool} scan - {reason}: target={target!r} options={options!r}")
        return {
            'success': False,
            'error': reason,
            'tool': tool,
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
        }

    def _run_nmap_docker(self, target, scan_options):
        """Run nmap μέσω Docker container - argv list, never a shell string."""
        container = None
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

            # scan_options/target were already validated by run_nmap_scan(); this
            # is defense-in-depth in case this method is ever called directly.
            if not validate_target(target) or not validate_nmap_options(scan_options):
                return self._invalid_input_result('nmap', target, scan_options, 'Invalid or unsafe input')

            nmap_args = scan_options.split() + [target]

            # Run scan detached so we can enforce a hard wall-clock timeout and
            # guarantee cleanup instead of leaking an orphaned container.
            container = self.docker_client.containers.run(
                "instrumentisto/nmap",
                nmap_args,
                remove=False,
                detach=True,
            )

            timed_out = False
            try:
                container.wait(timeout=NMAP_CONTAINER_TIMEOUT_SECONDS)
            except Exception:
                timed_out = True

            output = container.logs(stdout=True, stderr=True).decode('utf-8', errors='replace')

            if timed_out:
                error_msg = f"nmap container scan timed out after {NMAP_CONTAINER_TIMEOUT_SECONDS}s"
                print(f"❌ {error_msg}")
                return {
                    'success': False,
                    'error': error_msg,
                    'tool': 'nmap',
                    'target': target,
                    'scan_options': scan_options,
                    'timestamp': datetime.utcnow().isoformat(),
                    'method': 'docker',
                }

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
                'method': 'docker',
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
                'method': 'docker',
            }
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception as cleanup_error:
                    print(f"⚠️ Could not remove nmap container: {cleanup_error}")

    def _run_nmap_direct(self, target, scan_options):
        """Run nmap directly χωρίς Docker - argv list, shell=False."""
        try:
            print(f"⚡ Running nmap directly (no Docker)")

            if not validate_target(target) or not validate_nmap_options(scan_options):
                return self._invalid_input_result('nmap', target, scan_options, 'Invalid or unsafe input')

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

            cmd = ["nmap"] + scan_options.split() + [target]
            print(f"   Command: {' '.join(cmd)}")

            process = subprocess.Popen(
                cmd,
                shell=False,
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

        if not validate_target(target):
            return self._invalid_input_result('nuclei', target, template_type, 'Invalid or unsafe target')
        if not validate_nuclei_template(template_type):
            return self._invalid_input_result('nuclei', target, template_type, 'Invalid or unsafe template type')

        if not self.docker_client:
            return {
                'success': False,
                'error': 'Docker not available for nuclei scan',
                'tool': 'nuclei',
                'target': target,
                'template_type': template_type,
                'timestamp': datetime.utcnow().isoformat()
            }

        container = None
        try:
            # Έλεγχος εικόνας
            try:
                self.docker_client.images.get("projectdiscovery/nuclei")
                print("✅ Nuclei image already exists")
            except docker.errors.ImageNotFound:
                print("📥 Pulling nuclei image...")
                self.docker_client.images.pull("projectdiscovery/nuclei")
                print("✅ Nuclei image pulled")

            # argv list, never a shell string.
            nuclei_args = ["-u", target, "-t", template_type, "-silent", "-json"]
            print(f"🐳 Running nuclei via Docker: {' '.join(nuclei_args)}")

            container = self.docker_client.containers.run(
                "projectdiscovery/nuclei",
                nuclei_args,
                remove=False,
                detach=True,
            )

            timed_out = False
            try:
                container.wait(timeout=NUCLEI_CONTAINER_TIMEOUT_SECONDS)
            except Exception:
                timed_out = True

            output = container.logs(stdout=True, stderr=True).decode('utf-8', errors='replace')

            if timed_out:
                error_msg = f"nuclei container scan timed out after {NUCLEI_CONTAINER_TIMEOUT_SECONDS}s"
                print(f"❌ {error_msg}")
                return {
                    'success': False,
                    'error': error_msg,
                    'tool': 'nuclei',
                    'target': target,
                    'template_type': template_type,
                    'timestamp': datetime.utcnow().isoformat()
                }

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
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception as cleanup_error:
                    print(f"⚠️ Could not remove nuclei container: {cleanup_error}")

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
