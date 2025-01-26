![631a0622b83f655630f90a88_GBUzueM7nxxM0tfrtdYonVtfa8xZqedDb0U8pAxaNJgc3PXgnIIxR8BvXmdDlqcGx3wNoUWVFvMEOLR8qwdFPdFsJNGE-d8aM5zIw6woDuafgcidSyJYWhySFOW-gWvXRyT4rZMfrI-U9FRmIRk9c0su3vLCZ69zu7lh51uJuI555_25KCqzIpGq1A](https://github.com/user-attachments/assets/5de10ba8-48e1-4139-a9f1-b3a3fe7d6cac)

# DisclosureSearch

> **A comprehensive Bug Bounty helper for discovering information disclosure.**  

## Overview

**DisclosureSearch** is a multi-threaded, automated scanning tool to find **information disclosure** across multiple subdomains. It integrates with [**Katana**](https://github.com/projectdiscovery/katana) to gather a large set of possible paths for each subdomain and then performs a **BFS crawl** internally to discover additional URLs and look for secrets using **extensive regex checks**.

---

## Features

1. **Katana Integration**  
   - Automatically triggers Katana against each target to fetch potential endpoints with a high level of depth and concurrency.

2. **Breadth-First Search (BFS) Crawler**  
   - Recursively crawls discovered pages to a configurable depth (`-d, --depth`) and collects new links that match the same domain.

3. **Multi-Threading**  
   - Executes scans concurrently using Python’s `ThreadPoolExecutor`, greatly speeding up scanning on large lists of subdomains.

4. **Diverse Regex Detection**  
   - Matches AWS keys, Google API keys, potential credentials, session tokens, Slack tokens, internal IPs, MD5/SHA1/SHA256/Bcrypt hashes, private SSH keys, etc.

5. **Clear & Colorful CLI Output**  
   - Prints progress messages, warnings, and errors with color-coded logs (via [**Colorama**](https://pypi.org/project/colorama/)).

6. **Comprehensive Reporting**  
   - Generates a **clean text report** (default `disclosures.txt`) containing all detected disclosures per subdomain.

---

## Installation

1. **Clone or Download** this repository.  
2. **Install dependencies**:
   ```bash
   pip3 install -r requirements.txt
   ```
Make sure you have Katana installed and available in your PATH:
```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest
```
3. **Run**:
   ```bash
    python3 disclosure_search.py -s subdomains.txt -o disclosures_report.txt
   ```
# Usage
```bash
python3 disclosure_search.py \
    -s /path/to/subdomains.txt \
    -o /path/to/output.txt \
    -w 20 \
    -d 3
```

Argument	Description	Default
-s, --subdomains	File with subdomains to scan (one per line).	Required
-o, --output	File to store the final disclosure report.	disclosures.txt
-w, --workers	Number of worker threads for concurrency.	10
-d, --depth	BFS Depth for internal crawling of found URLs.	2

# Example Workflow
1. Prepare your subdomain file subdomains.txt
  ```
  sub1.example.com
  sub2.example.com
  api.example.com
  ...
  ```

2. **Execute DisclosureSearch**
```bash
python3 disclosure_search.py -s subdomains.txt -o found_disclosures.txt -w 20 -d 3
```
![imagen](https://github.com/user-attachments/assets/04d42d7d-c0c2-41cf-959e-83423c965df8)


3. **Monitor CLI logs:**
- See the colorful messages that show each subdomain scan, BFS progress, and any errors.

4. Check your report:
- All findings (AWS Keys, tokens, hashed passwords, etc.) are listed inside found_disclosures.txt.

![imagen](https://github.com/user-attachments/assets/fb88dc01-824b-4c92-9f98-d250053e8243)


# Important Notes
- Intended Use: This tool aims to support authorized bug bounty or penetration testing programs.
- Performance Caution: High BFS depth + large subdomain lists can produce heavy load. Tweak -w (workers) and -d (depth) accordingly.
- False Positives: Because the regex set is extremely broad, some false positives are inevitable. Always verify findings manually.
- Legal Warning: Use responsibly and with explicit permission. Unauthorized scanning of systems is illegal and unethical.

