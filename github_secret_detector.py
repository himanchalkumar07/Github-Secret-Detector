import requests, re, json

PATTERNS = {
    "password": r"(password|passwd|pwd)\s*=\s*['\"]?([^\s'\"#]+)",
    "token": r"(token|api[_-]?key|auth)\s*=\s*['\"]?([^\s'\"#]+)",
    "sql": r"(mysql|db|database|user|host)\s*=\s*['\"]?([^\s'\"#]+)",
    "private_key": r"-----BEGIN .*PRIVATE KEY-----.*?-----END .*PRIVATE KEY-----",
}

def safe_get(url, headers=None):
    try:
        return requests.get(url, headers=headers, timeout=10)
    except:
        return None

def search(target, token):
    url = f'https://api.github.com/search/code?q="{target}" in:file&per_page=10'
    r = safe_get(url, {"Authorization": f"token {token}"})
    return r.json().get("items", []) if (r and r.status_code == 200) else []

def scan(raw):
    out = []
    lines = raw.splitlines()
    for i, line in enumerate(lines, 1):
        for t, p in PATTERNS.items():
            if re.search(p, line, re.I | re.S):
                out.append({"type": t, "line": i, "match": line.strip()})
    return out

def main():
    target = input("Target keyword/domain: ")
    token = input("GitHub Token: ")

    items = search(target, token)
    results_json = []

    if not items:
        print("No results or unable to connect.")
        return

    for f in items:
        raw_url = f["html_url"].replace("https://github.com/", "https://raw.githubusercontent.com/").replace("/blob/","/")
        r = safe_get(raw_url)
        if not r:
            continue

        leaks = scan(r.text)
        if leaks:
            entry = {
                "repo": f["repository"]["full_name"],
                "file": f["path"],
                "url": f["html_url"],
                "leaks": leaks
            }
            results_json.append(entry)

            print("\nRepo:", entry["repo"])
            print("File:", entry["file"])
            print("URL :", entry["url"])
            for l in leaks:
                print(f"\n[!] {l['type']}  | Line {l['line']}")
                print(l["match"])

    print("\n\n========== JSON OUTPUT ==========")
    print(json.dumps(results_json, indent=4))

if __name__ == "__main__":
    main()


