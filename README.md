# GitHub Secret Detection Script

A Python-based OSINT tool that identifies sensitive information leaked in public GitHub repositories related to a specific target keyword or domain name.

---

## Features
- Searches GitHub public repositories using the GitHub Code Search API.
- Detects:
  - Passwords  
  - API keys  
  - SQL credentials  
  - Private keys  
  - Tokens / Authorization strings  
  - Server IPs  
  - `.env` and configuration file leaks  
- Extracts:
  - Exact line number of the leak  
  - Leaked line content  
  - Repository name  
  - File path  
  - Match type (password, token, etc.)  
  - Direct GitHub URL  

---

##  How to Use This Script

### **1️ Requirements**
- Python 3.8 or higher  
- An active GitHub Personal Access Token  
  (with `public_repo` or `repo` permissions)

---

## **2️ Running the Script**

### **Option A: Run Directly**
```bash
python3 secret_scanner.py
