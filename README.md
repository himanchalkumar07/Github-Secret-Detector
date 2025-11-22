# GitHub Secret Leak Scanner
Lightweight Python tool to detect leaked credentials, passwords, API keys, and sensitive information across public GitHub repositories using the GitHub Code Search API.

This tool helps security researchers, bug bounty hunters, and red teamers quickly identify exposed secrets related to a specific target domain, keyword, or company name.

---

## Features

### GitHub API-Powered Secret Scanning
Searches public GitHub repositories for files containing your target keyword or domain.

### Detects Multiple Secret Types
Built-in regex signatures detect:
- API keys
- Tokens (Auth, Bearer, OAuth)
- Passwords and credentials
- Database secrets
- Private keys
- Hardcoded configs and hosts

### Precise Leak Details
For each secret found, the tool extracts:
- Repository name  
- File path  
- GitHub URL  
- Line number of the leak  
- Exact leaked line  
- Type of leak (password, token, SQL, etc.)

### JSON Output
Produces clean JSON for automation, pipeline integration, dashboards, or SIEM ingestion.

---

## Installation

```bash
pip install requests
