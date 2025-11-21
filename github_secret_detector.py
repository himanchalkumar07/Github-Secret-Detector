#!/usr/bin/env python3
"""
GitHub Secret Scanner
Detect exposed credentials in public repositories

Built for Detox Technologies Internship
Author: [Your Name]
"""

import requests
import json
import re
import time
import sys
import base64
from datetime import datetime

class SecretHunter:
    def __init__(self, github_token):
        self.token = github_token
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'token {github_token}',
            'User-Agent': 'SecretScanner-1.0'
        })
        
        # Secret patterns I've seen in real code audits
        self.patterns = {
            'password': [
                re.compile(r'password\s*=\s*[\'"]([^\'"]+)[\'"]', re.I),
                re.compile(r'passwd\s*=\s*[\'"]([^\'"]+)[\'"]', re.I),
                re.compile(r'pwd\s*=\s*[\'"]([^\'"]+)[\'"]', re.I)
            ],
            'api_key': [
                re.compile(r'api[_-]?key\s*=\s*[\'"]([a-zA-Z0-9]{20,40})[\'"]', re.I),
                re.compile(r'api[_-]?token\s*=\s*[\'"]([a-zA-Z0-9]{20,40})[\'"]', re.I)
            ],
            'database': [
                re.compile(r'mysql://[^:]+:([^@]+)@', re.I),
                re.compile(r'postgres://[^:]+:([^@]+)@', re.I),
                re.compile(r'db_password\s*=\s*[\'"]([^\'"]+)[\'"]', re.I)
            ],
            'secret_key': [
                re.compile(r'secret[_-]?key\s*=\s*[\'"]([^\'"]+)[\'"]', re.I),
                re.compile(r'private[_-]?key\s*=\s*[\'"]([^\'"]+)[\'"]', re.I)
            ],
            'config': [
                re.compile(r'\.env', re.I),
                re.compile(r'config/.*\.(yml|yaml|json)', re.I)
            ]
        }
    
    def search_github(self, target, max_pages=3):
        """Main search function - looks for target across GitHub"""
        print(f"[*] Starting scan for: {target}")
        print(f"[*] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        all_findings = []
        
        # Different ways to search for the target
        search_queries = [
            f'"{target}"',
            f'{target}.com',
            f'@{target}',
            f'{target}.in'
        ]
        
        for query in search_queries:
            print(f"[*] Searching: {query}")
            findings = self._search_query(query, max_pages)
            all_findings.extend(findings)
            
            # Be nice to GitHub API
            time.sleep(1)
        
        print(f"[+] Scan complete. Found {len(all_findings)} potential issues")
        return all_findings
    
    def _search_query(self, query, max_pages):
        """Handle actual GitHub API search"""
        findings = []
        page = 1
        
        while page <= max_pages:
            try:
                # GitHub code search endpoint
                url = 'https://api.github.com/search/code'
                params = {
                    'q': query,
                    'per_page': 30,
                    'page': page
                }
                
                resp = self.session.get(url, params=params)
                
                # Handle rate limits
                if resp.status_code == 403:
                    reset_time = resp.headers.get('X-RateLimit-Reset')
                    if reset_time:
                        wait_time = int(reset_time) - time.time() + 10
                        print(f"[!] Rate limited. Waiting {wait_time:.0f} seconds...")
                        time.sleep(max(wait_time, 1))
                    continue
                
                if resp.status_code != 200:
                    print(f"[!] API error: {resp.status_code}")
                    break
                
                data = resp.json()
                
                # No more results
                if not data.get('items'):
                    break
                
                print(f"[+] Page {page}: {len(data['items'])} files")
                
                # Check each file found
                for file_item in data['items']:
                    file_findings = self._check_file(file_item, query)
                    findings.extend(file_findings)
                
                page += 1
                time.sleep(0.5)  # Be polite to API
                
            except Exception as e:
                print(f"[!] Error in search: {e}")
                break
        
        return findings
    
    def _check_file(self, file_item, original_query):
        """Analyze a single file for secrets"""
        findings = []
        
        try:
            # Get file metadata
            repo_name = file_item['repository']['full_name']
            file_path = file_item['path']
            file_url = file_item['html_url']
            
            # Skip binary/large files
            if self._should_skip_file(file_path):
                return findings
            
            # Get actual file content
            content = self._get_file_content(file_item['git_url'])
            if not content:
                return findings
            
            # Scan each line
            lines = content.split('\n')
            for line_num, line in enumerate(lines, 1):
                line_findings = self._scan_line(line, line_num, repo_name, file_path, file_url, original_query)
                findings.extend(line_findings)
                
        except Exception as e:
            print(f"[!] Error checking {file_item.get('path', 'unknown')}: {e}")
        
        return findings
    
    def _get_file_content(self, git_url):
        """Fetch file content from GitHub"""
        try:
            resp = self.session.get(git_url)
            if resp.status_code == 200:
                content_data = resp.json()
                # GitHub returns content as base64
                content_b64 = content_data.get('content', '')
                if content_b64:
                    return base64.b64decode(content_b64).decode('utf-8', errors='ignore')
        except Exception as e:
            print(f"[!] Failed to get content: {e}")
        
        return None
    
    def _scan_line(self, line, line_num, repo_name, file_path, file_url, target):
        """Scan a single line for secrets"""
        findings = []
        
        # Skip empty lines and comments
        line_clean = line.strip()
        if not line_clean or line_clean.startswith('#'):
            return findings
        
        # Check if line is relevant to our target
        if not self._is_relevant_to_target(line, target):
            return findings
        
        # Test against all secret patterns
        for secret_type, patterns in self.patterns.items():
            for pattern in patterns:
                matches = pattern.findall(line)
                for match in matches:
                    if match:  # Found something!
                        finding = {
                            'repo': repo_name,
                            'file': file_path,
                            'line': line_num,
                            'secret_type': secret_type,
                            'matched_text': self._mask_secret(str(match)),
                            'full_line': self._mask_line(line),
                            'url': f"{file_url}#L{line_num}",
                            'target': target,
                            'timestamp': datetime.now().isoformat()
                        }
                        findings.append(finding)
        
        return findings
    
    def _is_relevant_to_target(self, line, target):
        """Check if line actually contains our target"""
        target_variants = [
            target,
            target.replace('.', '_'),
            target.replace('.', '-'),
            f'@{target}',
            f'//{target}'
        ]
        
        line_lower = line.lower()
        return any(variant.lower() in line_lower for variant in target_variants)
    
    def _mask_secret(self, secret):
        """Mask secrets for safety"""
        if len(secret) <= 4:
            return '***'
        return secret[:2] + '***' + secret[-2:]
    
    def _mask_line(self, line):
        """Mask sensitive parts of a line"""
        # Simple masking for demo - in real use, be more careful
        masked = re.sub(r'([a-zA-Z0-9]{20,})', lambda m: self._mask_secret(m.group(1)), line)
        return masked
    
    def _should_skip_file(self, file_path):
        """Skip binary or irrelevant files"""
        skip_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.pdf', '.exe', '.dll']
        skip_patterns = ['node_modules/', 'dist/', 'build/', '.git/']
        
        if any(file_path.endswith(ext) for ext in skip_extensions):
            return True
        if any(pattern in file_path for pattern in skip_patterns):
            return True
        
        return False


def main():
    """Main execution - handles command line and runs the scan"""
    print("GitHub Secret Scanner v1.0")
    print("=" * 40)
    
    # Simple command line handling
    if len(sys.argv) >= 3:
        target = sys.argv[1]
        token = sys.argv[2]
        output_file = sys.argv[3] if len(sys.argv) > 3 else 'scan_results.json'
    else:
        # Interactive mode
        print("\nEnter scan details:")
        target = input("Target (company/domain): ").strip()
        token = input("GitHub token: ").strip()
        output_file = input("Output file [scan_results.json]: ").strip() or 'scan_results.json'
    
    if not target or not token:
        print("[!] Need both target and token")
        sys.exit(1)
    
    # Run the scan
    scanner = SecretHunter(token)
    results = scanner.search_github(target)
    
    # Save results
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Show summary
    print(f"\n[*] Results saved to: {output_file}")
    if results:
        print(f"[+] Found {len(results)} potential issues:")
        for result in results[:5]:  # Show first 5
            print(f"  - {result['repo']} : {result['file']}:{result['line']}")
    else:
        print("[-] No issues found (this is good for security!)")


if __name__ == '__main__':
    main()
