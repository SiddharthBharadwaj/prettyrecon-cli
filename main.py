import argparse
from pathlib import Path
import sys
import time
from typing import Set, List, Optional
import validators
import requests
from bs4 import BeautifulSoup
from requests.exceptions import RequestException
import json
import shutil
from datetime import datetime
import signal
import uuid

from config import Colors, ScanConfig, APIConfig, CustomScanConfig
from exceptions import AuthenticationError, ScanError, OutputError, ValidationError

class PrettyReconScanner:
    # Common scan configurations
    SCAN_CONFIGS = {
        'subdomains': {
            'name': 'subdomains',
            'endpoint': 'subdomains',
            'output_file': 'subdomains.json',
            'columns': 9
        },
        'dns_scan': {
            'name': 'DNS records',
            'endpoint': 'dns_scan',
            'output_file': 'dnsinfo.json',
            'columns': 4
        },
        'ports': {
            'name': 'ports',
            'endpoint': 'ports',
            'output_file': 'ports.json',
            'columns': 3
        },
        'wayback_urls': {
            'name': 'wayback URLs',
            'endpoint': 'urls',
            'output_file': 'waybackurls.json',
            'columns': 1
        },
        'common_vulnerability': {
            'name': 'common vulnerabilities',
            'endpoint': 'common_vulnerability',
            'output_file': 'common_vulns.json',
            'columns': 4
        },
        'exposed_secrets': {
            'name': 'exposed secrets',
            'endpoint': 'exposed_secrets',
            'output_file': 'exposed_creds.json',
            'columns': 4
        },
        'cves': {
            'name': 'CVEs',
            'endpoint': 'cves',
            'output_file': 'cves.json',
            'columns': 4
        }
    }

    SCAN_TYPE_PATHS = {
        'sub': ['subdomains'],
        'basic': ['subdomains', 'dns_scan', 'ports', 'wayback_urls'],
        'vuln': ['subdomains', 'common_vulnerability', 'exposed_secrets', 'cves'],
        'all': ['subdomains', 'dns_scan', 'ports', 'wayback_urls', 
                'common_vulnerability', 'exposed_secrets', 'cves']
    }

    def __init__(self, config: ScanConfig):
        self.config = config
        self.session = self._init_session()
        self.running_jobs: Set[str] = set()
        self.job_list: List[str] = []
        self.base_url = f'{APIConfig.BASE_URL}/target/{config.target}'
        self._interrupted = False
        self._current_scan = None
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        if self._current_scan:
            print(f"\n{Colors.YELLOW}Interrupted while fetching {self._current_scan}. Saving partial results...{Colors.ENDC}")
            self._interrupted = True
        else:
            print(f"\n{Colors.YELLOW}Interrupted. Exiting...{Colors.ENDC}")
            sys.exit(0)

    def _init_session(self) -> requests.Session:
        """Initialize requests session with default headers"""
        session = requests.Session()
        session.headers.update(APIConfig.HEADERS)
        return session

    def _get_common_headers(self, referer: str) -> dict:
        """Get common headers for API requests"""
        return {
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Origin': APIConfig.BASE_URL,
            'Referer': referer,
            'X-Csrftoken': self.session.cookies.get('csrftoken', '')
        }

    def _get_request_data(self, start: int, length: int, num_columns: int = 4) -> dict:
        """Generate common request data structure for API calls"""
        data = {
            'draw': '1',
            'order[0][column]': '0',
            'order[0][dir]': 'asc',
            'start': str(start),
            'length': str(length),
            'search[value]': '',
            'search[regex]': 'false',
            'iindex': '0',
            'isearch[]': '',
            'eindex': '0',
            'esearch[]': ''
        }
        
        # Add column definitions
        for i in range(num_columns):
            data.update({
                f'columns[{i}][data]': str(i),
                f'columns[{i}][name]': '',
                f'columns[{i}][searchable]': 'true',
                f'columns[{i}][orderable]': 'true',
                f'columns[{i}][search][value]': '',
                f'columns[{i}][search][regex]': 'false'
            })
        
        return data

    def _fetch_paginated_data(self, endpoint: str, headers: dict, request_data_func, output_file: str, scan_name: str) -> None:
        """Fetch paginated data from an API endpoint"""
        self._current_scan = scan_name
        self._interrupted = False
        
        try:
            # Get initial response to determine total records
            response = self.session.post(
                endpoint,
                headers=headers,
                data=request_data_func(0, 100),
                timeout=APIConfig.REQUEST_TIMEOUT
            )

            if not response.ok:
                print(f"{Colors.FAIL}Error: Received status code {response.status_code}{Colors.ENDC}")
                print(f"Response content: {response.text[:500]}...")
                raise ScanError(f"{scan_name} API request failed with status code {response.status_code}")

            try:
                data = response.json()
                total_records = data.get('recordsFiltered', 0)
                print(f"{Colors.BLUE}Found {total_records} {scan_name}{Colors.ENDC}")

                # Initialize list to store all records
                all_records = []

                # Fetch all pages
                for start in range(0, total_records, 100):
                    if self._interrupted:
                        break
                        
                    print(f"{Colors.BLUE}Fetching {scan_name} {start+1}-{min(start+100, total_records)}{Colors.ENDC}")
                    print(f"{Colors.YELLOW}Press Ctrl+C to skip remaining records{Colors.ENDC}")
                    
                    response = self.session.post(
                        endpoint,
                        headers=headers,
                        data=request_data_func(start, 100),
                        timeout=APIConfig.REQUEST_TIMEOUT
                    )
                    
                    if not response.ok:
                        print(f"{Colors.FAIL}Error: Received status code {response.status_code}{Colors.ENDC}")
                        print(f"Response content: {response.text[:500]}...")
                        raise ScanError(f"{scan_name} API request failed with status code {response.status_code}")
                    
                    try:
                        page_data = response.json()
                        if 'data' in page_data:
                            all_records.extend(page_data['data'])
                        else:
                            print(f"{Colors.YELLOW}Warning: No 'data' field in response{Colors.ENDC}")
                            print(f"Response content: {response.text[:500]}...")
                    except json.JSONDecodeError as e:
                        print(f"{Colors.FAIL}Error: Invalid JSON response{Colors.ENDC}")
                        print(f"Response content: {response.text[:500]}...")
                        raise ScanError(f"Failed to parse {scan_name} JSON response: {str(e)}")
                    
                    time.sleep(1)  # Be nice to the API

                # Create final data structure
                final_data = {
                    'data': all_records,
                    'recordsTotal': total_records,
                    'recordsFiltered': total_records,
                    'partial_fetch': self._interrupted
                }
                self.save_json_output(final_data, output_file)
                
                if self._interrupted:
                    print(f"{Colors.YELLOW}Successfully saved {len(all_records)} {scan_name} (partial results){Colors.ENDC}")
                else:
                    print(f"{Colors.GREEN}Successfully saved {len(all_records)} {scan_name}{Colors.ENDC}")

            except json.JSONDecodeError as e:
                print(f"{Colors.FAIL}Error: Invalid JSON response{Colors.ENDC}")
                print(f"Response content: {response.text[:500]}...")
                raise ScanError(f"Failed to parse {scan_name} JSON response: {str(e)}")

        finally:
            self._current_scan = None

    def login(self) -> None:
        """Authenticate with PrettyRecon"""
        try:
            response = self.session.get(
                APIConfig.LOGIN_URL,
                timeout=APIConfig.REQUEST_TIMEOUT
            )
            csrf_token = self.session.cookies.get('csrftoken')
            
            email, password = APIConfig.get_credentials()
            login_data = {
                "csrfmiddlewaretoken": csrf_token,
                "email": email,
                "password": password
            }
            
            response = self.session.post(
                APIConfig.LOGIN_URL,
                data=login_data,
                timeout=APIConfig.REQUEST_TIMEOUT
            )
            
            if 'Invalid credentials' in response.text:
                raise AuthenticationError("Login failed: Invalid credentials")
            elif 'Dashboard Summary' not in response.text:
                raise AuthenticationError("Login failed: Unexpected response")
                
            print(f"{Colors.GREEN}Login successful!{Colors.ENDC}")
            time.sleep(2)  # Allow session to stabilize
            
        except RequestException as e:
            raise AuthenticationError(f"Network error during login: {str(e)}")

    def _init_jobs(self, flag: int = 0) -> None:
        """Initialize or update job tracking"""
        try:
            response = self.session.get(
                APIConfig.JOBS_URL,
                timeout=APIConfig.REQUEST_TIMEOUT
            )
            current_jobs = set(self._extract_job_ids(response.text))
            
            if flag == 0:
                self.running_jobs = current_jobs
            else:
                new_jobs = current_jobs - self.running_jobs
                for job_id in new_jobs:
                    print(f"Job with ID {job_id} Started!")
                    self.job_list.append(job_id)
                    
        except RequestException as e:
            raise ScanError(f"Error tracking jobs: {str(e)}")

    def _extract_job_ids(self, content: str) -> List[str]:
        """Extract job IDs from response content"""
        import re
        pattern = r'[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}'
        return re.findall(pattern, content)

    def _monitor_jobs(self) -> None:
        """Monitor running jobs until completion"""
        try:
            while True:
                response = self.session.get(
                    APIConfig.JOBS_URL,
                    timeout=APIConfig.REQUEST_TIMEOUT
                )
                current_jobs = self._extract_job_ids(response.text)
                
                if not any(job_id in self.job_list for job_id in current_jobs):
                    break
                    
                sys.stdout.write('■')
                sys.stdout.flush()
                time.sleep(5)
                
        except RequestException as e:
            raise ScanError(f"Error monitoring jobs: {str(e)}")

    def save_json_output(self, data: dict, filename: str) -> None:
        """Save JSON data to output directory"""
        if self.config.output_dir:
            try:
                self.config.output_dir.mkdir(parents=True, exist_ok=True)
                output_file = self.config.output_dir / filename
                
                with output_file.open('w') as f:
                    json.dump(data, f, indent=2)
                    
            except (OSError, IOError) as e:
                raise OutputError(f"Error saving to {filename}: {str(e)}")

    def _fetch_scan_data(self, scan_paths: list) -> None:
        """Fetch data for given scan paths"""
        if not self.config.output:
            return

        for scan_path in scan_paths:
            if scan_path not in self.SCAN_CONFIGS:
                continue

            config = self.SCAN_CONFIGS[scan_path]
            print(f"\n{Colors.BOLD}Fetching {config['name']}...{Colors.ENDC}")
            
            endpoint = f"{APIConfig.BASE_URL}/api/data/{config['endpoint']}/{self.config.target}"
            referer = f"{self.base_url}/{scan_path}/"
            headers = self._get_common_headers(referer)
            
            self._fetch_paginated_data(
                endpoint,
                headers,
                lambda start, length: self._get_request_data(start, length, num_columns=config['columns']),
                config['output_file'],
                config['name']
            )

    def _initialize_scans(self, scan_paths: list) -> None:
        """Initialize scans for given paths"""
        for scan_path in scan_paths:
            if scan_path not in self.SCAN_CONFIGS:
                continue
                
            config = self.SCAN_CONFIGS[scan_path]
            print(f"{Colors.BOLD}Scanning for {config['name']}...{Colors.ENDC}")
            self.session.get(f"{self.base_url}/{scan_path}/", timeout=APIConfig.REQUEST_TIMEOUT)
            time.sleep(1)

    def vulnerability_scan(self) -> None:
        """Perform vulnerability scan"""
        try:
            scan_paths = self.SCAN_TYPE_PATHS['vuln'][1:]  # Exclude subdomains
            self._initialize_scans(scan_paths)
            
            self._init_jobs(1)
            if self.config.output:
                self._monitor_jobs()
                self._fetch_scan_data(scan_paths)
                
        except Exception as e:
            raise ScanError(f"Vulnerability scan failed: {str(e)}")

    def basic_scan(self) -> None:
        """Perform basic reconnaissance scan"""
        try:
            scan_paths = self.SCAN_TYPE_PATHS['basic'][1:]  # Exclude subdomains
            self._initialize_scans(scan_paths)
            
            self._init_jobs(1)
            if self.config.output:
                self._monitor_jobs()
                self._fetch_scan_data(scan_paths)
                
        except Exception as e:
            raise ScanError(f"Basic scan failed: {str(e)}")

    def rescan(self) -> None:
        """Retrigger scans based on scan type"""
        print(f"{Colors.BOLD}Retriggering scans for type: {self.config.scan_type}...{Colors.ENDC}")
        
        scan_paths = self.SCAN_TYPE_PATHS.get(self.config.scan_type.lower(), [])
        if not scan_paths:
            raise ValidationError(f"Invalid scan type for rescan: {self.config.scan_type}")
        
        # Check and handle running tasks first
        self._wait_for_tasks(scan_paths)
        
        # Reset job tracking and trigger rescans
        self._init_jobs(0)
        for scan_path in scan_paths:
            self._trigger_rescan(scan_path)
            time.sleep(2)
        
        # Initialize new jobs and monitor them
        if self.config.output:
            self._init_jobs(1)
            print(f"\n{Colors.BOLD}Waiting for scans to complete...{Colors.ENDC}")
            self._monitor_jobs()
            print(f"\n{Colors.BOLD}Fetching scan results...{Colors.ENDC}")
            self._fetch_scan_data(scan_paths)

    def _trigger_rescan(self, scan_path: str) -> None:
        """Trigger a rescan for a specific scan type"""
        try:
            rescan_url = f"{self.base_url}/{scan_path}/"
            csrf_token = self.session.cookies.get('csrftoken', '')
            
            # First visit the page to ensure proper session state
            self.session.get(rescan_url, timeout=APIConfig.REQUEST_TIMEOUT)
            
            # Trigger the rescan
            data = {
                'csrfmiddlewaretoken': csrf_token,
                'action': 'rescan'
            }
            headers = {
                'Origin': APIConfig.BASE_URL,
                'Referer': rescan_url,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Upgrade-Insecure-Requests': '1'
            }
            
            response = self.session.post(
                rescan_url,
                data=data,
                headers=headers,
                timeout=APIConfig.REQUEST_TIMEOUT
            )
            
            if response.ok:
                print(f"{Colors.GREEN}Successfully triggered rescan for {scan_path}{Colors.ENDC}")
            else:
                print(f"{Colors.FAIL}Failed to trigger rescan for {scan_path}: {response.status_code}{Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.FAIL}Error triggering rescan for {scan_path}: {str(e)}{Colors.ENDC}")

    def _get_running_tasks(self) -> list:
        """Get list of currently running tasks"""
        try:
            response = self.session.get(
                APIConfig.JOBS_URL,
                headers={'Upgrade-Insecure-Requests': '1'},
                timeout=APIConfig.REQUEST_TIMEOUT
            )
            
            if not response.ok:
                print(f"{Colors.FAIL}Failed to fetch running tasks: {response.status_code}{Colors.ENDC}")
                return []
            
            # Parse HTML response using BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            tasks = []
            for task_div in soup.find_all('div', class_='p-5 rounded-lg flex flex-col gap-4'):
                domain = task_div.find('p', class_='font-bold text-xl')
                if not domain:
                    continue
                
                domain_text = domain.text.strip()
                if domain_text != self.config.target:
                    continue
                
                scan_type = task_div.find('span', class_='p-2')
                if not scan_type:
                    continue
                
                stop_button = task_div.find('button')
                if not stop_button:
                    continue
                
                task_id = None
                onclick = stop_button.get('@click', '')
                import re
                match = re.search(r"'([a-f0-9-]+)'", onclick)
                if match:
                    task_id = match.group(1)
                
                tasks.append({
                    'domain': domain_text,
                    'scan_type': scan_type.text.strip(),
                    'task_id': task_id
                })
            
            return tasks
            
        except Exception as e:
            print(f"{Colors.FAIL}Error fetching running tasks: {str(e)}{Colors.ENDC}")
            return []

    def _stop_task(self, task_id: str) -> bool:
        """Stop a running task"""
        try:
            csrf_token = self.session.cookies.get('csrftoken', '')
            stop_url = f"{APIConfig.BASE_URL}/tasks/"
            
            data = {
                'csrfmiddlewaretoken': csrf_token,
                'task_id': task_id,
                'action': 'stop'
            }
            
            headers = {
                'Origin': APIConfig.BASE_URL,
                'Referer': stop_url,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Upgrade-Insecure-Requests': '1'
            }
            
            response = self.session.post(
                stop_url,
                data=data,
                headers=headers,
                timeout=APIConfig.REQUEST_TIMEOUT
            )
            
            if response.ok:
                print(f"{Colors.GREEN}Successfully stopped task {task_id}{Colors.ENDC}")
                return True
            else:
                print(f"{Colors.FAIL}Failed to stop task {task_id}: {response.status_code}{Colors.ENDC}")
                return False
            
        except Exception as e:
            print(f"{Colors.FAIL}Error stopping task {task_id}: {str(e)}{Colors.ENDC}")
            return False

    def _wait_for_tasks(self, scan_paths: list) -> None:
        """Wait for running tasks to complete or stop them"""
        if not self.config.output:
            return
        
        print(f"{Colors.BOLD}Checking for running tasks...{Colors.ENDC}")
        
        while True:
            tasks = self._get_running_tasks()
            if not tasks:
                break
            
            print(f"\nFound {len(tasks)} running tasks for {self.config.target}:")
            for task in tasks:
                print(f"- {task['scan_type']} (Task ID: {task['task_id']})")
            
            choice = input(f"\n{Colors.YELLOW}Do you want to stop these tasks? (y/n, default: y): {Colors.ENDC}").lower()
            if choice != 'n':
                for task in tasks:
                    if task['task_id']:
                        self._stop_task(task['task_id'])
                break
            
            print(f"\n{Colors.BLUE}Waiting 10 seconds before checking again...{Colors.ENDC}")
            time.sleep(10)

    def custom_subdomain_scan(self) -> None:
        """Perform custom subdomain scan with file input"""
        try:
            if not self.config.custom_subscan_file or not self.config.custom_subscan_file.exists():
                raise ValidationError("Custom subscan file not found")
            
            # Read targets from file
            with self.config.custom_subscan_file.open('r') as f:
                targets = [line.strip() for line in f if line.strip()]
            
            if not targets:
                raise ValidationError("No targets found in the file")
            
            # Generate scan name with UUID and timestamp
            scan_name = f"autopretty-{uuid.uuid4()}-{int(datetime.now().timestamp())}"
            
            # Process targets in chunks of 300
            chunk_size = 300
            for i in range(0, len(targets), chunk_size):
                chunk = targets[i:i + chunk_size]
                
                # Get CSRF token and session cookies
                response = self.session.get(
                    f"{APIConfig.BASE_URL}/tools/custom_subdomains/",
                    headers={
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                        'Accept-Language': 'en-GB,en;q=0.9',
                        'Cache-Control': 'max-age=0',
                        'Sec-Fetch-Dest': 'document',
                        'Sec-Fetch-Mode': 'navigate',
                        'Sec-Fetch-Site': 'same-origin',
                        'Sec-Fetch-User': '?1',
                        'Upgrade-Insecure-Requests': '1'
                    },
                    timeout=APIConfig.REQUEST_TIMEOUT
                )
                
                if not response.ok:
                    raise ScanError(f"Failed to access custom subdomains page: {response.status_code}")
                
                csrf_token = self.session.cookies.get('csrftoken', '')
                if not csrf_token:
                    raise ScanError("Failed to get CSRF token")
                
                # Prepare and send the request
                data = {
                    'csrfmiddlewaretoken': csrf_token,
                    'scan_name': scan_name,
                    'targets': '\r\n'.join(chunk)  # Use \r\n as in the working request
                }
                
                headers = {
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Accept-Language': 'en-GB,en;q=0.9',
                    'Cache-Control': 'max-age=0',
                    'Origin': APIConfig.BASE_URL,
                    'Referer': f"{APIConfig.BASE_URL}/tools/custom_subdomains/",
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'same-origin',
                    'Sec-Fetch-User': '?1',
                    'Upgrade-Insecure-Requests': '1'
                }
                
                response = self.session.post(
                    f"{APIConfig.BASE_URL}/tools/custom_subdomains/",
                    data=data,
                    headers=headers,
                    timeout=APIConfig.REQUEST_TIMEOUT,
                    allow_redirects=False
                )
                
                if response.status_code == 302:
                    scan_id = response.headers.get('Location', '').split('/')[-1]
                    if scan_id:
                        print(f"{Colors.GREEN}Successfully started custom scan batch {i//chunk_size + 1} "
                              f"(targets {i+1}-{min(i+chunk_size, len(targets))}):{Colors.ENDC}")
                        print(f"Scan Name: {scan_name}")
                        print(f"Scan ID: {scan_id}")
                    else:
                        print(f"{Colors.FAIL}Failed to get scan ID from Location header{Colors.ENDC}")
                else:
                    print(f"{Colors.FAIL}Failed to start custom scan: {response.status_code}{Colors.ENDC}")
                    if response.text:
                        print(f"Response content: {response.text[:500]}...")
                
                time.sleep(2)  # Add delay between batches
                
        except Exception as e:
            raise ScanError(f"Custom subdomain scan failed: {str(e)}")

    def subdomain_scan(self) -> None:
        """Perform subdomain scan"""
        try:
            scan_paths = ['subdomains']
            self._initialize_scans(scan_paths)
            self._init_jobs(1)
            if self.config.output:
                self._monitor_jobs()
                self._fetch_scan_data(scan_paths)
        except Exception as e:
            raise ScanError(f"Subdomain scan failed: {str(e)}")

    def run(self) -> None:
        """Main execution flow"""
        try:
            self.login()
            
            if self.config.custom_subscan_file:
                self.custom_subdomain_scan()
            else:
                self._init_jobs(0)
                
                scan_types = {
                    'all': [self.subdomain_scan, self.basic_scan, self.vulnerability_scan],
                    'basic': [self.subdomain_scan, self.basic_scan],
                    'vuln': [self.subdomain_scan, self.vulnerability_scan],
                    'sub': [self.subdomain_scan]
                }
                
                scan_functions = scan_types.get(self.config.scan_type.lower())
                if not scan_functions:
                    raise ValidationError(f"Invalid scan type: {self.config.scan_type}")
                    
                for scan_func in scan_functions:
                    scan_func()
                    
        except Exception as e:
            print(f"{Colors.FAIL}Scan failed: {str(e)}{Colors.ENDC}")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='PrettyRecon CLI')
    parser.add_argument("-t", "--target", help="Supply the target to scan.")
    parser.add_argument("-st", "--scan_type", help="all: Full scan, basic: Basic scan, vuln: Scan for vulns only, sub: Subdomains only")
    parser.add_argument("-o", "--output", help="Saves output to output/*.json file.", action='store_true')
    parser.add_argument("-cscn", "--customsubscan", help="For the CustomSubScan feature of PrettyRecon. Pass filename after flag.")
    parser.add_argument("-r", "--rescan", help="Retrigger scans based on scan type", action='store_true')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.target and not args.customsubscan:
        parser.error("Either -t/--target or -cscn/--customsubscan is required")
        
    if args.target and not args.scan_type:
        parser.error("Missing argument '-st/--scan_type' when using -t/--target")
        
    if args.target and not validators.domain(args.target):
        print(f"{Colors.FAIL}Invalid target format. Example: example.com [Without http(s) and '/']{Colors.ENDC}")
        sys.exit(1)
        
    # Create configuration
    config = ScanConfig(
        target=args.target,
        scan_type=args.scan_type,
        output=bool(args.output),
        custom_subscan_file=Path(args.customsubscan) if args.customsubscan else None
    )
    
    # Initialize and run scanner
    scanner = PrettyReconScanner(config)
    
    if args.rescan:
        scanner.login()
        scanner.rescan()
    else:
        scanner.run()

if __name__ == '__main__':
    main()