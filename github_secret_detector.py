import requests
import base64
import re
import json
import sys
import time


SEARCH_API = "https://api.github.com/search/code"

# Cache for ETags to avoid rate limits
etag_cache = {}


SENSITIVE_PATTERNS = {
    "password": r"(?:pass|pwd|password)\s*[:=]\s*['\"]?([^\s'\"#]+)",
    "api_key": r"(?:api[_-]?key|apikey|token)\s*[:=]\s*['\"]?([^\s'\"#]+)",
    "secret": r"(?:secret|secret_key)\s*[:=]\s*['\"]?([^\s'\"#]+)",
    "sql_credentials": r"(?:db_pass|db_password|mysql_pass|sql_pass)\s*[:=]\s*['\"]?([^\s'\"#]+)",
    "private_key": r"-----BEGIN PRIVATE KEY-----",
    "auth": r"(?:auth|authorization)\s*[:=]\s*['\"]?([^\s'\"#]+)",
    "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}


def get_user_inputs():
    print("\nGitHub Sensitive Data Scanner\n")
    keyword = input("Enter target keyword or domain name: ").strip()
    token = input("Enter GitHub Personal Access Token: ").strip()

    if not keyword or not token:
        print("Missing keyword or token.")
        sys.exit(1)

    return keyword, token


def github_search(token, query):
    headers = {"Authorization": f"token {token}"}
    params = {"q": query, "per_page": 30}

    response = requests.get(SEARCH_API, headers=headers, params=params)

    if response.status_code != 200:
        print("GitHub API error:", response.text)
        sys.exit(1)

    return response.json().get("items", [])


def fetch_file_via_api(token, repo, path, branch):

    url = f"https://api.github.com/repos/{repo}/contents/{path}?ref={branch}"

    headers = {"Authorization": f"token {token}"}

    # Use ETag caching to avoid rate limits
    if url in etag_cache:
        headers["If-None-Match"] = etag_cache[url]

    response = requests.get(url, headers=headers)

    # ETag hit, no download required (does not count to rate limit)
    if response.status_code == 304:
        return etag_cache[url]["content"]

    if response.status_code != 200:
        return None

    # Save new ETag
    if "ETag" in response.headers:
        etag_cache[url] = {
            "etag": response.headers["ETag"],
            "content": response.json()
        }

    return response.json()


def extract_file_content(api_response):
    if not api_response:
        return None

    content = api_response.get("content", "")
    encoding = api_response.get("encoding", "")

    if encoding == "base64":
        try:
            return base64.b64decode(content).decode("utf-8", errors="ignore")
        except:
            return None

    return None


def scan_for_leaks(content):
    findings = []

    for number, line in enumerate(content.split("\n"), start=1):
        for leak_type, pattern in SENSITIVE_PATTERNS.items():
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                value = match.group(1) if match.groups() else line.strip()
                findings.append({
                    "line_number": number,
                    "line": line.strip(),
                    "type": leak_type,
                    "value": value
                })
    return findings


def build_search_queries(keyword):
    return [
        keyword,
        f"\"{keyword}\"",
        f"{keyword} in:file",
        f"{keyword} extension:env",
        f"{keyword} extension:json",
        f"\"{keyword}\" extension:yaml",
        f"{keyword} extension:ini",
    ]


def main():
    keyword, token = get_user_inputs()
    queries = build_search_queries(keyword)

    all_results = []

    for q in queries:
        print(f"Searching: {q}")
        results = github_search(token, q)

        for item in results:
            repo = item["repository"]["full_name"]
            path = item["path"]
            branch = item["repository"]["default_branch"]
            html_url = item["html_url"]

            api_file = fetch_file_via_api(token, repo, path, branch)
            if not api_file:
                continue

            content = extract_file_content(api_file)
            if not content:
                continue

            leaks = scan_for_leaks(content)

            for leak in leaks:
                entry = {
                    "repo": repo,
                    "file": path,
                    "line_number": leak["line_number"],
                    "match_type": leak["type"],
                    "value": leak["value"],
                    "line": leak["line"],
                    "github_url": html_url
                }
                all_results.append(entry)

                print("\n----------------------------")
                print("Repository:", repo)
                print("File:", path)
                print("Line:", leak["line_number"])
                print("Type:", leak["type"])
                print("Value:", leak["value"])
                print("Matched Line:", leak["line"])
                print("URL:", html_url)
                print("----------------------------\n")

        time.sleep(1)  # slow down to avoid further rate limits

    with open("results.json", "w") as f:
        json.dump(all_results, f, indent=4)

    if not all_results:
        print("No sensitive information detected.")
    else:
        print("Results saved to results.json")


if __name__ == "__main__":
    main()

