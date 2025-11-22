GitHub Sensitive Data Scanner

This script automates the process of identifying exposed sensitive information across public GitHub repositories based on a target keyword or domain name. It uses the GitHub Code Search API and the GitHub Contents API to fetch file contents, scan the data, and extract exact leak details.

Features
--------

• Search GitHub for files containing your target keyword.  
• Fetch raw file contents through GitHub API.  
• Detect common sensitive patterns such as:  
  - Passwords  
  - API keys  
  - Secrets  
  - SQL credentials  
  - IP addresses  
  - Authorization tokens  
  - Private keys  
• Extracts:  
  - Line number  
  - File path  
  - Repo name  
  - Matched secret  
  - Leak type  
  - Exact matched line  
  - GitHub URL  
• Saves results into a structured results.json file.

Requirements
------------

• Python 3.8+  
• GitHub Personal Access Token  
• Internet connection  

Install dependencies:
---------------------

    pip install requests

Generate GitHub Personal Access Token
-------------------------------------

1. Login to GitHub: https://github.com  
2. Go to **Settings**  
3. Navigate to **Developer settings → Personal access tokens → Tokens (classic)**  
4. Click **Generate new token**  
5. Select the following scopes:  
      - public_repo  
      - read:user  
6. Click **Generate token**  
7. Copy the token (you won't be able to view it again).  
8. Use it directly in the script when prompted.
