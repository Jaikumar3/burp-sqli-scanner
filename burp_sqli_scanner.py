#!/usr/bin/env python3
"""
Burp Suite SQL Injection Testing Automation Tool
Automates SQL injection testing from Burp Suite history logs using Ghauri and SQLMap
"""

import argparse
import json
import csv
import os
import re
import subprocess
import threading
import time
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs


class BurpLogParser:
    """Parse Burp Suite history logs and extract HTTP requests"""
    
    def __init__(self, log_file: str, deduplicate: bool = True, dedup_method: str = 'url_method'):
        self.log_file = log_file
        self.requests = []
        self.deduplicate = deduplicate
        self.dedup_method = dedup_method
        self.seen_requests: Set[str] = set()
        self.duplicate_count = 0
    
    def _generate_request_hash(self, request_data: Dict[str, Any]) -> str:
        """Generate a hash for request deduplication based on the selected method"""
        if self.dedup_method == 'url_method':
            # Basic deduplication: URL + method
            url = f"{request_data.get('host', '')}{request_data.get('path', '')}"
            method = request_data.get('method', '')
            hash_input = f"{method}:{url}"
        
        elif self.dedup_method == 'url_method_params':
            # Include URL parameters in deduplication
            url = f"{request_data.get('host', '')}{request_data.get('path', '')}"
            method = request_data.get('method', '')
            # Extract parameters from URL and body
            params = self._extract_parameters(request_data)
            param_str = '&'.join(sorted(f"{k}={v}" for k, v in params.items()))
            hash_input = f"{method}:{url}:{param_str}"
        
        elif self.dedup_method == 'full_request':
            # Full request deduplication (excluding dynamic headers like timestamps)
            filtered_headers = self._filter_dynamic_headers(request_data.get('headers', {}))
            headers_str = '&'.join(sorted(f"{k}:{v}" for k, v in filtered_headers.items()))
            hash_input = f"{request_data.get('method', '')}:{request_data.get('host', '')}{request_data.get('path', '')}:{headers_str}:{request_data.get('body', '')}"
        
        else:  # 'none' - no deduplication
            import uuid
            return str(uuid.uuid4())
        
        return hashlib.md5(hash_input.encode('utf-8')).hexdigest()
    
    def _extract_parameters(self, request_data: Dict[str, Any]) -> Dict[str, str]:
        """Extract parameters from URL query string and request body"""
        params = {}
        
        # Extract from URL query string
        path = request_data.get('path', '')
        if '?' in path:
            query_string = path.split('?', 1)[1]
            for param in query_string.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params[key] = value
        
        # Extract from form data in body
        body = request_data.get('body', '')
        content_type = request_data.get('headers', {}).get('Content-Type', '')
        
        if 'application/x-www-form-urlencoded' in content_type:
            for param in body.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params[key] = value
        
        return params
    
    def _filter_dynamic_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Filter out dynamic headers that change between requests"""
        dynamic_headers = {
            'date', 'timestamp', 'x-request-id', 'x-correlation-id',
            'x-trace-id', 'x-span-id', 'cache-control', 'if-modified-since',
            'if-none-match', 'x-csrf-token', 'x-xsrf-token'
        }
        
        filtered = {}
        for key, value in headers.items():
            if key.lower() not in dynamic_headers:
                filtered[key] = value
        
        return filtered
    
    def _is_duplicate(self, request_data: Dict[str, Any]) -> bool:
        """Check if request is a duplicate based on the configured method"""
        if not self.deduplicate:
            return False
        
        request_hash = self._generate_request_hash(request_data)
        
        if request_hash in self.seen_requests:
            self.duplicate_count += 1
            return True
        
        self.seen_requests.add(request_hash)
        return False
    
    def parse_burp_log(self) -> List[Dict[str, Any]]:
        """Parse Burp Suite log file and extract HTTP requests"""
        try:
            # Handle different Burp log formats
            if self.log_file.endswith('.xml'):
                return self._parse_xml_log()
            else:
                return self._parse_text_log()
        except Exception as e:
            print(f"Error parsing log file: {e}")
            return []
    
    def _parse_xml_log(self) -> List[Dict[str, Any]]:
        """Parse XML format Burp log"""
        requests = []
        try:
            tree = ET.parse(self.log_file)
            root = tree.getroot()
            
            for item in root.findall('.//item'):
                request_data = {}
                
                # Extract basic info
                host = item.find('host')
                port = item.find('port')
                protocol = item.find('protocol')
                
                if host is not None:
                    request_data['host'] = host.text
                if port is not None:
                    request_data['port'] = port.text
                if protocol is not None:
                    request_data['protocol'] = protocol.text
                
                # Extract request
                request_elem = item.find('request')
                if request_elem is not None:
                    # Decode base64 if needed
                    import base64
                    if request_elem.get('base64') == 'true':
                        request_data['raw_request'] = base64.b64decode(request_elem.text).decode('utf-8', errors='ignore')
                    else:
                        request_data['raw_request'] = request_elem.text
                
                if 'raw_request' in request_data:
                    parsed_request = self._parse_raw_request(request_data['raw_request'])
                    request_data.update(parsed_request)
                    
                    # Check for duplicates
                    if not self._is_duplicate(request_data):
                        requests.append(request_data)
                    
        except Exception as e:
            print(f"Error parsing XML log: {e}")
        
        if self.duplicate_count > 0:
            print(f"Filtered out {self.duplicate_count} duplicate requests")
        
        return requests
    
    def _parse_text_log(self) -> List[Dict[str, Any]]:
        """Parse text format Burp log"""
        requests = []
        
        with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Split by request boundaries (this may need adjustment based on your log format)
        request_blocks = re.split(r'\n={20,}\n|\n-{20,}\n', content)
        
        for block in request_blocks:
            if not block.strip():
                continue
                
            # Look for HTTP request patterns
            http_match = re.search(r'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s]+)\s+HTTP/[\d.]+', block)
            if http_match:
                request_data = self._parse_raw_request(block)
                if request_data and not self._is_duplicate(request_data):
                    requests.append(request_data)
        
        if self.duplicate_count > 0:
            print(f"Filtered out {self.duplicate_count} duplicate requests")
        
        return requests
    
    def _parse_raw_request(self, raw_request: str) -> Dict[str, Any]:
        """Parse raw HTTP request text"""
        lines = raw_request.strip().split('\n')
        if not lines:
            return {}
        
        # Parse request line
        request_line = lines[0].strip()
        match = re.match(r'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s]+)\s+HTTP/([\d.]+)', request_line)
        
        if not match:
            return {}
        
        method, path, http_version = match.groups()
        
        # Parse headers
        headers = {}
        body = ""
        body_start = len(lines)
        
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == "":
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        # Parse body
        if body_start < len(lines):
            body = '\n'.join(lines[body_start:])
        
        # Extract host from headers
        host = headers.get('Host', '')
        
        return {
            'method': method,
            'path': path,
            'http_version': http_version,
            'headers': headers,
            'body': body,
            'host': host,
            'raw_request': raw_request
        }


class SQLiTester:
    """SQL Injection testing using Ghauri and SQLMap"""
    
    def __init__(self, output_dir: str = "sqli_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.results = []
    
    def save_request_file(self, request: Dict[str, Any], index: int) -> str:
        """Save request to file for tool consumption"""
        filename = f"request_{index}.txt"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            f.write(request['raw_request'])
        
        return str(filepath)
    
    def test_with_ghauri(self, request_file: str, request_data: Dict[str, Any], show_output: bool = True, extra_args: Optional[list] = None) -> Dict[str, Any]:
        """Run Ghauri on a request file"""
        result = {
            'tool': 'ghauri',
            'request_file': request_file,
            'host': request_data.get('host', ''),
            'method': request_data.get('method', ''),
            'path': request_data.get('path', ''),
            'vulnerable': False,
            'injection_type': None,
            'exploitable_params': [],
            'output': '',
            'error': None
        }
        
        try:
            # Build Ghauri command
            cmd = [
                'ghauri',
                '-r', request_file,
                '--batch',
                '--level', '3',
                '--threads', '5'
            ]
            if extra_args:
                cmd += extra_args
            
            # Run Ghauri - always show command as part of full activity display
            print(f"Running command: {' '.join(cmd)}")
            
            # Show real-time output if requested
            if show_output:
                print(f"\n{'='*60}")
                print(f"GHAURI OUTPUT for {request_data.get('host', '')}{request_data.get('path', '')}")
                print(f"{'='*60}")
                
                # Run with real-time output
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                full_output = ""
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        print(output.strip())
                        full_output += output
                
                process.wait()
                print(f"{'='*60}")
                result['output'] = full_output
                
            else:
                # Capture output without display
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minute timeout
                )
                
                full_output = process.stdout
                if process.stderr:
                    full_output += "\n--- STDERR ---\n" + process.stderr
                
                result['output'] = full_output
            
            if process.returncode == 0:
                # Parse Ghauri output for vulnerabilities
                if 'Parameter' in result['output'] and 'vulnerable' in result['output'].lower():
                    result['vulnerable'] = True
                    result['injection_type'] = self._extract_injection_type(result['output'])
                    result['exploitable_params'] = self._extract_parameters(result['output'])
            else:
                result['error'] = f"Ghauri exited with code {process.returncode}"
                
        except subprocess.TimeoutExpired:
            result['error'] = 'Ghauri timeout (5 minutes)'
        except FileNotFoundError:
            result['error'] = 'Ghauri not found. Please install Ghauri.'
        except Exception as e:
            result['error'] = str(e)
            if 'process' in locals():
                try:
                    process.terminate()
                except:
                    pass
        
        return result
    
    def test_with_sqlmap(self, request_file: str, request_data: Dict[str, Any], show_output: bool = True, extra_args: Optional[list] = None) -> Dict[str, Any]:
        """Run SQLMap on a request file"""
        result = {
            'tool': 'sqlmap',
            'request_file': request_file,
            'host': request_data.get('host', ''),
            'method': request_data.get('method', ''),
            'path': request_data.get('path', ''),
            'vulnerable': False,
            'injection_type': None,
            'exploitable_params': [],
            'output': '',
            'error': None
        }
        
        try:
            # Build SQLMap command
            cmd = [
                'sqlmap',
                '-r', request_file,
                '--batch',
                '--level', '3',
                '--risk', '3',
                '--threads', '5',
                '--technique', 'BEUSTQ'
            ]
            if extra_args:
                cmd += extra_args
            
            # Run SQLMap - always show command as part of full activity display
            print(f"Running command: {' '.join(cmd)}")
            
            # Show real-time output if requested
            if show_output:
                print(f"\n{'='*60}")
                print(f"SQLMAP OUTPUT for {request_data.get('host', '')}{request_data.get('path', '')}")
                print(f"{'='*60}")
                
                # Run with real-time output
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                full_output = ""
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        print(output.strip())
                        full_output += output
                
                process.wait()
                print(f"{'='*60}")
                result['output'] = full_output
                
            else:
                # Capture output without display
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minute timeout
                )
                
                full_output = process.stdout
                if process.stderr:
                    full_output += "\n--- STDERR ---\n" + process.stderr
                
                result['output'] = full_output
            
            if process.returncode == 0:
                # Parse SQLMap output for vulnerabilities
                if 'Parameter' in result['output'] and 'vulnerable' in result['output'].lower():
                    result['vulnerable'] = True
                    result['injection_type'] = self._extract_injection_type(result['output'])
                    result['exploitable_params'] = self._extract_parameters(result['output'])
            else:
                result['error'] = f"SQLMap exited with code {process.returncode}"
                
        except subprocess.TimeoutExpired:
            result['error'] = 'SQLMap timeout (5 minutes)'
        except FileNotFoundError:
            result['error'] = 'SQLMap not found. Please install SQLMap.'
        except Exception as e:
            result['error'] = str(e)
            if 'process' in locals():
                try:
                    process.terminate()
                except:
                    pass
        
        return result
    
    def _extract_injection_type(self, output: str) -> Optional[str]:
        """Extract injection type from tool output"""
        # Look for common injection types
        injection_types = [
            'boolean-based blind',
            'time-based blind',
            'error-based',
            'union query',
            'stacked queries'
        ]
        
        for injection_type in injection_types:
            if injection_type in output.lower():
                return injection_type
        
        return None
    
    def _extract_parameters(self, output: str) -> List[str]:
        """Extract vulnerable parameters from tool output"""
        params = []
        
        # Look for parameter patterns in output
        param_patterns = [
            r'Parameter:\s+([^\s\n]+)',
            r'vulnerable parameter[:\s]+([^\s\n]+)',
            r'Parameter \'([^\']+)\' is vulnerable'
        ]
        
        for pattern in param_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            params.extend(matches)
        
        return list(set(params))  # Remove duplicates
    
    def test_request(self, request: Dict[str, Any], index: int, tools: List[str], show_output: bool = True, extra_args: Optional[list] = None) -> List[Dict[str, Any]]:
        """Test a single request with specified tools"""
        request_file = self.save_request_file(request, index)
        results = []
        
        if 'ghauri' in tools:
            print(f"Testing request {index} with Ghauri...")
            result = self.test_with_ghauri(request_file, request, show_output, extra_args)
            # Save Ghauri output to file
            output_file = self.output_dir / f"output_{index}_ghauri.txt"
            with open(output_file, 'w') as f:
                f.write(result['output'])
            results.append(result)
        
        if 'sqlmap' in tools:
            print(f"Testing request {index} with SQLMap...")
            result = self.test_with_sqlmap(request_file, request, show_output, extra_args)
            # Save SQLMap output to file
            output_file = self.output_dir / f"output_{index}_sqlmap.txt"
            with open(output_file, 'w') as f:
                f.write(result['output'])
            results.append(result)
        
        return results
    
    def test_requests_concurrent(self, requests: List[Dict[str, Any]], tools: List[str], max_workers: int = 5, show_output: bool = True, extra_args: Optional[list] = None) -> List[Dict[str, Any]]:
        """Test multiple requests concurrently"""
        all_results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_index = {
                executor.submit(self.test_request, request, i, tools, show_output, extra_args): i
                for i, request in enumerate(requests)
            }
            
            # Collect results
            for future in as_completed(future_to_index):
                index = future_to_index[future]
                try:
                    results = future.result()
                    all_results.extend(results)
                    print(f"Completed testing request {index}")
                except Exception as e:
                    print(f"Error testing request {index}: {e}")
        
        return all_results
    
    def test_requests_sequential(self, requests: List[Dict[str, Any]], tools: List[str], show_output: bool = True, extra_args: Optional[list] = None) -> List[Dict[str, Any]]:
        """Test requests one by one"""
        all_results = []
        
        for i, request in enumerate(requests):
            print(f"Testing request {i+1}/{len(requests)}")
            results = self.test_request(request, i, tools, show_output, extra_args)
            all_results.extend(results)
        
        return all_results


class ReportGenerator:
    """Generate reports from SQL injection test results"""
    
    @staticmethod
    def generate_json_report(results: List[Dict[str, Any]], output_file: str, duplicate_count: int = 0):
        """Generate JSON report"""
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'total_requests': len(set(r['request_file'] for r in results)),
            'vulnerable_requests': len([r for r in results if r['vulnerable']]),
            'duplicates_filtered': duplicate_count,
            'results': results
        }
        
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"JSON report saved to {output_file}")
    
    @staticmethod
    def generate_csv_report(results: List[Dict[str, Any]], output_file: str):
        """Generate CSV report"""
        if not results:
            return
        
        fieldnames = [
            'tool', 'request_file', 'host', 'method', 'path',
            'vulnerable', 'injection_type', 'exploitable_params', 'error'
        ]
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                row = {k: v for k, v in result.items() if k in fieldnames}
                # Convert list to string for CSV
                if isinstance(row.get('exploitable_params'), list):
                    row['exploitable_params'] = ', '.join(row['exploitable_params'])
                writer.writerow(row)
        
        print(f"CSV report saved to {output_file}")
    
    @staticmethod
    def print_summary(results: List[Dict[str, Any]], duplicate_count: int = 0):
        """Print summary of results"""
        total_requests = len(set(r['request_file'] for r in results))
        vulnerable_results = [r for r in results if r['vulnerable']]
        vulnerable_requests = len(set(r['request_file'] for r in vulnerable_results))
        
        print("\n" + "="*50)
        print("SQL INJECTION TESTING SUMMARY")
        print("="*50)
        print(f"Total requests tested: {total_requests}")
        if duplicate_count > 0:
            print(f"Duplicate requests filtered: {duplicate_count}")
        print(f"Vulnerable requests found: {vulnerable_requests}")
        print(f"Vulnerability rate: {(vulnerable_requests/total_requests)*100:.2f}%" if total_requests > 0 else "N/A")
        
        if vulnerable_results:
            print("\nVulnerable requests:")
            for result in vulnerable_results:
                print(f"  - {result['host']}{result['path']} ({result['method']}) - {result['tool']}")
                if result['injection_type']:
                    print(f"    Type: {result['injection_type']}")
                if result['exploitable_params']:
                    print(f"    Parameters: {', '.join(result['exploitable_params'])}")


def main():
    parser = argparse.ArgumentParser(description='Automate SQL injection testing from Burp Suite logs')
    parser.add_argument('log_file', help='Burp Suite log file (.log or .xml)')
    parser.add_argument('-t', '--tools', nargs='+', choices=['ghauri', 'sqlmap'], 
                       help='Tools to use for testing (default: none - just parse and save requests)')
    parser.add_argument('-o', '--output', default='sqli_results', 
                       help='Output directory for results')
    parser.add_argument('--concurrent', action='store_true', 
                       help='Run tests concurrently (default: sequential)')
    parser.add_argument('--max-workers', type=int, default=5, 
                       help='Maximum concurrent workers (default: 5)')
    parser.add_argument('--json-report', help='JSON report output file')
    parser.add_argument('--csv-report', help='CSV report output file')
    
    # Duplicate handling options
    parser.add_argument('--no-deduplicate', action='store_true',
                       help='Disable duplicate request filtering')
    # Deduplication method is always url_method (default, not user-configurable)
    
    # Output control options
    parser.add_argument('--quiet', action='store_true',
                       help='Suppress tool output display (still saved in reports)')
    parser.add_argument('--tool-args', nargs=argparse.REMAINDER, default=[],
                       help='Extra arguments to pass to Ghauri/SQLMap (e.g. --dbms mysql --auth-token TOKEN)')
    
    args = parser.parse_args()
    
    # Set default tools if none specified (empty list means just parse, don't run tools)
    if not args.tools:
        args.tools = []
    
    # Check if log file exists
    if not os.path.exists(args.log_file):
        print(f"Error: Log file {args.log_file} not found")
        return 1
    
    # Determine deduplication settings
    deduplicate = not args.no_deduplicate
    dedup_method = 'none' if args.no_deduplicate else 'url_method'
    
    # Parse Burp log
    print(f"Parsing Burp log: {args.log_file}")
    if deduplicate:
        print(f"Deduplication enabled (method: url_method)")
    else:
        print("Deduplication disabled")
        
    log_parser = BurpLogParser(args.log_file, deduplicate=deduplicate, dedup_method=dedup_method)
    requests = log_parser.parse_burp_log()
    
    if not requests:
        print("No HTTP requests found in log file")
        return 1
    
    print(f"Found {len(requests)} HTTP requests")
    
    # Initialize tester
    tester = SQLiTester(args.output)
    
    # Save all requests to individual files
    print(f"Saving requests to {args.output} directory...")
    for i, request in enumerate(requests, 1):
        request_file = tester.save_request_file(request, i)
        print(f"Saved: {request_file}")
    
    # Only run tools if specified
    if args.tools:
        print(f"\nRunning SQL injection tests with tools: {', '.join(args.tools)}")
        
        # Determine output settings
        show_output = not args.quiet
        
        # Run tests
        if args.concurrent:
            print(f"Running tests concurrently with {args.max_workers} workers...")
            results = tester.test_requests_concurrent(requests, args.tools, args.max_workers, show_output, args.tool_args)
        else:
            print("Running tests sequentially...")
            results = tester.test_requests_sequential(requests, args.tools, show_output, args.tool_args)
        
        # Generate reports
        report_gen = ReportGenerator()
        
        if args.json_report:
            report_gen.generate_json_report(results, args.json_report, log_parser.duplicate_count)
        
        if args.csv_report:
            report_gen.generate_csv_report(results, args.csv_report)
        
        # Print summary
        report_gen.print_summary(results, log_parser.duplicate_count)
    else:
        print(f"\nRequest parsing complete! {len(requests)} requests saved.")
        print("Use -t ghauri and/or -t sqlmap to run SQL injection tests.")
    
    return 0


if __name__ == '__main__':
    exit(main())
