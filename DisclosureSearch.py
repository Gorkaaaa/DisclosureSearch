#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
import urllib.parse
import concurrent.futures
import threading
import subprocess
import queue
import time
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = ""
        GREEN = ""
        YELLOW = ""
        CYAN = ""
        RESET = ""
    class Style:
        RESET_ALL = ""
    print("Instala 'colorama' para ver los colores en la salida (pip install colorama)")

requests.packages.urllib3.disable_warnings()

# =========================================================================
# GIGANTESCA LISTA DE REGEX PARA DETECTAR SECRETOS, TOKENS, CLAVES, ETC.
# =========================================================================
PATTERNS = [
    # ------------------------ AWS ------------------------ #
    (re.compile(r'(AWS|aws)?_?(ACCESS|SECRET)?_?(KEY|KEY_ID|ACCESS_KEY_ID|SECRET_ACCESS_KEY)\s*[:=]\s*["\']?([A-Za-z0-9/\+=]{16,40})["\']?', re.IGNORECASE), "Possible AWS Key"),
    (re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE), "AWS Access Key ID"),
    (re.compile(r'ASIA[0-9A-Z]{16}', re.IGNORECASE), "AWS Temp Access Key"),
    (re.compile(r'(?i)aws(.{0,20})?secret(.{0,20})?=\s*[0-9a-zA-Z/+]{40}'), "AWS Secret Key"),

    # ------------------------ Google ------------------------ #
    (re.compile(r'AIza[0-9A-Za-z-_]{35}', re.IGNORECASE), "Google API Key"),
    (re.compile(r'\bGOOGLE_API_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{39})(?:"|\'|)', re.IGNORECASE), "Google API Key (var)"),
    (re.compile(r'\bGOOGLE_CLOUD_PROJECT\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "Google Cloud Project ID"),
    
    # ------------------------ Firebase ------------------------ #
    (re.compile(r'\bFIREBASE_API_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{40})(?:"|\'|)', re.IGNORECASE), "Firebase API Key"),
    (re.compile(r'\bFIREBASE_SECRET\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{40})(?:"|\'|)', re.IGNORECASE), "Firebase Secret"),

    # ------------------------ Azure ------------------------ #
    (re.compile(r'(?i)(AccountKey|SharedKey)\s*=\s*([A-Za-z0-9\+/=]{40,})'), "Azure Storage Key"),

    # ------------------------ Generic Tokens & Secrets ------------------------ #
    (re.compile(r'\bAPI[_-]?KEY\b\s*[:=]\s*["\']?([A-Za-z0-9-_+=]{8,})["\']?', re.IGNORECASE), "Generic API Key"),
    (re.compile(r'\bSECRET[_-]?KEY\b\s*[:=]\s*["\']?([A-Za-z0-9-_+=]{8,})["\']?', re.IGNORECASE), "Generic Secret Key"),
    (re.compile(r'\bTOKEN\s*[:=]\s*["\']?([A-Za-z0-9-_]{20,})["\']?', re.IGNORECASE), "Generic Token"),
    (re.compile(r'\bBEARER\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "Bearer Token"),
    (re.compile(r'\bPRIVATE[_-]?KEY\b\s*[:=]\s*["\']?([A-Za-z0-9-_=]+)["\']?', re.IGNORECASE), "Private Key"),
    (re.compile(r'-----BEGIN (RSA|EC|DSA)? PRIVATE KEY-----[\s\S]*?-----END (RSA|EC|DSA)? PRIVATE KEY-----'), "Complete Private Key Block"),

    # ------------------------ Slack ------------------------ #
    (re.compile(r'\bxox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}', re.IGNORECASE), "Slack Token"),
    (re.compile(r'\bSLACK_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{40,})(?:"|\'|)', re.IGNORECASE), "Slack Token (var)"),

    # ------------------------ Twilio ------------------------ #
    (re.compile(r'\bTWILIO_ACCOUNT_SID\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{34})(?:"|\'|)', re.IGNORECASE), "Twilio Account SID"),
    (re.compile(r'\bTWILIO_AUTH_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{32})(?:"|\'|)', re.IGNORECASE), "Twilio Auth Token"),

    # ------------------------ SendGrid ------------------------ #
    (re.compile(r'\bSENDGRID_API_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "SendGrid API Key"),
    (re.compile(r'\bSENDGRID_SECRET\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "SendGrid Secret Key"),

    # ------------------------ Mailgun ------------------------ #
    (re.compile(r'\bMAILGUN_API_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "Mailgun API Key"),

    # ------------------------ Stripe ------------------------ #
    (re.compile(r'\bSTRIPE_SECRET_KEY\s*[:=]\s*(?:"|\'|)([A-Za-z0-9-_]{32,})(?:"|\'|)', re.IGNORECASE), "Stripe Secret Key"),
    (re.compile(r'\bSTRIPE_PUBLISHABLE_KEY\s*[:=]\s*(?:"|\'|)([A-Za-z0-9-_]{32})(?:"|\'|)', re.IGNORECASE), "Stripe Publishable Key"),
    (re.compile(r'\bSTRIPE_API_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{32,})(?:"|\'|)', re.IGNORECASE), "Stripe API Key"),

    # ------------------------ GitHub ------------------------ #
    (re.compile(r'\bghp_[A-Za-z0-9]{36,40}', re.IGNORECASE), "GitHub Personal Access Token"),
    (re.compile(r'\bgithub_token\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{40,})(?:"|\'|)', re.IGNORECASE), "GitHub Token"),
    (re.compile(r'\bGITHUB_CLIENT_SECRET\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{40})(?:"|\'|)', re.IGNORECASE), "GitHub Client Secret"),

    # ------------------------ GitLab ------------------------ #
    (re.compile(r'\bglpat-[A-Za-z0-9-_]{20,}', re.IGNORECASE), "GitLab Personal Access Token"),
    (re.compile(r'\bGITLAB_PERSONAL_ACCESS_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "GitLab PAT (var)"),

    # ------------------------ Heroku ------------------------ #
    (re.compile(r'\bHEROKU_API_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{40})(?:"|\'|)', re.IGNORECASE), "Heroku API Key"),

    # ------------------------ Docker / NPM / SonarQube ------------------------ #
    (re.compile(r'\bDOCKER_CONFIG\s*:\s*(?:"|\'|)([A-Za-z0-9-_=\n]+)(?:"|\'|)', re.IGNORECASE), "Docker Config"),
    (re.compile(r'\bNPM_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{36})(?:"|\'|)', re.IGNORECASE), "NPM Token"),
    (re.compile(r'\bSONARQUBE_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{36})(?:"|\'|)', re.IGNORECASE), "SonarQube Token"),

    # ------------------------ Databases (genéricos) ------------------------ #
    (re.compile(r'\b(DB_PASSWORD|DATABASE_PASSWORD|DB_PASS)\s*[:=]\s*["\']?([A-Za-z0-9@#$%^&+=\-_!]{6,})["\']?', re.IGNORECASE), "Database Password"),

    # ------------------------ OAuth / Client Secrets / Bearer ------------------------ #
    (re.compile(r'(client_secret|app_secret)\s*[:=]\s*["\']?([A-Za-z0-9-_]{16,})["\']?', re.IGNORECASE), "OAuth Client Secret"),
    (re.compile(r'(authorization|api_key|api_token)\s*[:=]\s*["\']?([A-Za-z0-9-_]{16,})["\']?', re.IGNORECASE), "Auth / API Key"),

    # ------------------------ Contraseñas genéricas ------------------------ #
    (re.compile(r'\b(pass|password|passwd)\s*[:=]\s*["\']?([A-Za-z0-9@#$%^&*()_+!\-]{6,})["\']?', re.IGNORECASE), "Possible Password"),

    # ------------------------ Webhooks (Slack, Discord, etc.) ------------------------ #
    (re.compile(r'https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/]{20,}', re.IGNORECASE), "Slack Webhook"),
    (re.compile(r'https:\/\/discord\.com\/api\/webhooks\/[0-9]{18,}\/[A-Za-z0-9_-]{24,}', re.IGNORECASE), "Discord Webhook"),

    # ------------------------ 'Catch all' personalizable ------------------------ #
    (re.compile(r'(key|secret|token|pwd|pass|private)\s*[:=]\s*["\']?([A-Za-z0-9-_]{8,})["\']?', re.IGNORECASE), "Generic Sensitive Keyword"),
]

class DisclosureSearch:
    def __init__(self, subdomains_file, output_file, workers=10, max_depth=2):
        self.subdomains_file = subdomains_file
        self.output_file = output_file
        self.workers = workers
        self.max_depth = max_depth
        self.request_timeout = 15
        self.lock = threading.Lock()

    def color_print(self, text, color=Fore.GREEN, style=Style.RESET_ALL):
        print(color + text + style)

    def banner(self):
        banner = rf"""
{Fore.CYAN}{Style.BRIGHT}
▓█████▄  ██▓  ██████  ▄████▄   ██▓     ▒█████    ██████  █    ██  ██▀███  ▓█████ 
▒██▀ ██▌▓██▒▒██    ▒ ▒██▀ ▀█  ▓██▒    ▒██▒  ██▒▒██    ▒  ██  ▓██▒▓██ ▒ ██▒▓█   ▀ 
░██   █▌▒██▒░ ▓██▄   ▒▓█    ▄ ▒██░    ▒██░  ██▒░ ▓██▄   ▓██  ▒██░▓██ ░▄█ ▒▒███   
░▓█▄   ▌░██░  ▒   ██▒▒▓▓▄ ▄██▒▒██░    ▒██   ██░  ▒   ██▒▓▓█  ░██░▒██▀▀█▄  ▒▓█  ▄ 
░▒████▓ ░██░▒██████▒▒▒ ▓███▀ ░░██████▒░ ████▓▒░▒██████▒▒▒▒█████▓ ░██▓ ▒██▒░▒████▒
 ▒▒▓  ▒ ░▓  ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░░ ▒░▓  ░░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░░▒▓▒ ▒ ▒ ░ ▒▓ ░▒▓░░░ ▒░ ░
 ░ ▒  ▒  ▒ ░░ ░▒  ░ ░  ░  ▒   ░ ░ ▒  ░  ░ ▒ ▒░ ░ ░▒  ░ ░░░▒░ ░ ░   ░▒ ░ ▒░ ░ ░  ░
 ░ ░  ░  ▒ ░░  ░  ░  ░          ░ ░   ░ ░ ░ ▒  ░  ░  ░   ░░░ ░ ░   ░░   ░    ░   
   ░     ░        ░  ░ ░          ░  ░    ░ ░        ░     ░        ░        ░  ░
 ░                   ░                                                           
  ██████ ▓█████  ▄▄▄       ██▀███   ▄████▄   ██░ ██                              
▒██    ▒ ▓█   ▀ ▒████▄    ▓██ ▒ ██▒▒██▀ ▀█  ▓██░ ██▒                             
░ ▓██▄   ▒███   ▒██  ▀█▄  ▓██ ░▄█ ▒▒▓█    ▄ ▒██▀▀██░                             
  ▒   ██▒▒▓█  ▄ ░██▄▄▄▄██ ▒██▀▀█▄  ▒▓▓▄ ▄██▒░▓█ ░██                              
▒██████▒▒░▒████▒ ▓█   ▓██▒░██▓ ▒██▒▒ ▓███▀ ░░▓█▒░██▓                             
▒ ▒▓▒ ▒ ░░░ ▒░ ░ ▒▒   ▓▒█░░ ▒▓ ░▒▓░░ ░▒ ▒  ░ ▒ ░░▒░▒                             
░ ░▒  ░ ░ ░ ░  ░  ▒   ▒▒ ░  ░▒ ░ ▒░  ░  ▒    ▒ ░▒░ ░                             
░  ░  ░     ░     ░   ▒     ░░   ░ ░         ░  ░░ ░                             
      ░     ░  ░      ░  ░   ░     ░ ░       ░  ░  ░                             

      -> LinkedIn: {Fore.YELLOW}https://www.linkedin.com/in/gorka-el-bochi-morillo-4a5669240{Fore.RESET}
{Fore.CYAN}
============================================================{Fore.RESET}
        """
        print(banner)

    def normalize_url(self, url):
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        return url

    def run_katana(self, target):
        self.color_print(f"[KATANA] Ejecutando contra: {target}", Fore.CYAN)
        try:
            cmd = [
                "katana",
                "-u", target,
                "-d", "5",
                "-c", "50",
                "-silent",
                "-timeout", "10"
            ]
            output = subprocess.check_output(cmd, text=True)
            lines = [line.strip() for line in output.split("\n") if line.strip()]
            self.color_print(f"[KATANA] {target} => {len(lines)} rutas", Fore.YELLOW)
            return lines
        except Exception as e:
            self.color_print(f"[KATANA] Error en {target}: {e}", Fore.RED)
            return []

    def fetch_url(self, url):
        try:
            return requests.get(url, timeout=self.request_timeout, verify=False)
        except RequestException:
            return None

    def extract_links(self, base_url, response):
        ctype = response.headers.get("Content-Type", "").lower()
        if not ("text/html" in ctype or "application/xhtml+xml" in ctype):
            return []
        try:
            soup = BeautifulSoup(response.text, "html.parser")
        except:
            return []
        found = set()
        for tag in soup.find_all(["a", "link", "script", "img", "iframe"]):
            if tag.name in ["a", "link"]:
                attr = "href"
            else:
                attr = "src"
            link = tag.get(attr)
            if not link:
                continue
            absolute = urllib.parse.urljoin(base_url, link)
            found.add(absolute)
        return list(found)

    def search_sensitive_info(self, text):
        findings = []
        for pattern, label in PATTERNS:
            # Buscar todas las coincidencias
            matches = pattern.findall(text)
            if matches:
                for match in matches:
                    # Si la regex devuelve un group (tupla), convertirla en string
                    if isinstance(match, tuple):
                        # A veces la tupla es (captura, ) o (captura1, captura2,...)
                        # Mantenemos sólo la última parte si hay varios grupos
                        if len(match) > 1:
                            match = match[-1]
                        else:
                            match = match[0]
                    findings.append((label, match))
        return findings

    def threaded_crawl_worker(self, start_url, q, visited, results):
        while True:
            try:
                current_url, depth = q.get_nowait()
            except queue.Empty:
                return
            if depth > self.max_depth:
                q.task_done()
                continue
            with self.lock:
                if (current_url, depth) in visited:
                    q.task_done()
                    continue
                visited.add((current_url, depth))

            r = self.fetch_url(current_url)
            if r:
                new_findings = self.search_sensitive_info(r.text)
                if new_findings:
                    with self.lock:
                        for nf in new_findings:
                            results.append((nf[0], nf[1], current_url))
                if depth < self.max_depth:
                    same_domain = urllib.parse.urlparse(start_url).netloc
                    found_links = self.extract_links(current_url, r)
                    if found_links:
                        with self.lock:
                            self.color_print(f"[CRAWL] {current_url} => {len(found_links)} enlaces (nivel {depth+1})", Fore.YELLOW)
                    for link in found_links:
                        if urllib.parse.urlparse(link).netloc == same_domain:
                            q.put((link, depth + 1))

            q.task_done()

    def bfs_crawl(self, start_url, extra_paths):
        results = []
        q = queue.Queue()
        visited = set()

        q.put((start_url, 0))
        for p in extra_paths:
            q.put((p, 0))

        threads = []
        for _ in range(self.workers):
            t = threading.Thread(target=self.threaded_crawl_worker, args=(start_url, q, visited, results))
            t.daemon = True
            t.start()
            threads.append(t)

        start_time = time.time()
        q.join()
        elapsed = time.time() - start_time
        self.color_print(f"[CRAWL] BFS finalizado para {start_url}. Tiempo: {elapsed:.2f}s", Fore.GREEN)
        return results

    def scan_subdomain(self, subdomain):
        self.color_print(f"[INICIO] Escaneando: {subdomain}", Fore.CYAN)
        base = self.normalize_url(subdomain)
        data = {"subdomain": subdomain, "disclosures": []}

        katana_endpoints = self.run_katana(base)
        processed_paths = []
        for ep in katana_endpoints:
            if ep.startswith("http://") or ep.startswith("https://"):
                processed_paths.append(ep)
            else:
                processed_paths.append(urllib.parse.urljoin(base, ep))

        self.color_print(f"[CRAWL] {subdomain} => {len(processed_paths)} rutas iniciales de Katana", Fore.YELLOW)
        crawl_findings = self.bfs_crawl(base, processed_paths)
        if crawl_findings:
            self.color_print(f"[INFO] {subdomain} => {len(crawl_findings)} hallazgos", Fore.GREEN)

        for name, val, src_url in crawl_findings:
            data["disclosures"].append((name, val, src_url))

        return data

    def run(self):
        self.banner()
        with open(self.subdomains_file, "r", encoding="utf-8") as f:
            subdomains = [line.strip() for line in f if line.strip()]
        self.color_print(f"[CARGA] {len(subdomains)} subdominios leídos de {self.subdomains_file}", Fore.CYAN)

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as ex:
            future_to_sd = {ex.submit(self.scan_subdomain, s): s for s in subdomains}
            for future in concurrent.futures.as_completed(future_to_sd):
                sd = future_to_sd[future]
                try:
                    res = future.result()
                    results.append(res)
                except Exception as e:
                    self.color_print(f"[ERROR] {sd}: {e}", Fore.RED)

        self.generate_report(results)
        self.color_print(f"[FIN] Escaneo finalizado. Reporte => {self.output_file}", Fore.GREEN)

    def generate_report(self, results):
        with open(self.output_file, "w", encoding="utf-8") as f:
            for r in results:
                f.write(f"=== {r['subdomain']} ===\n")
                if r["disclosures"]:
                    f.write("Disclosures:\n")
                    for name, val, origin_url in r["disclosures"]:
                        f.write(f" - [{name}] {val} (Origen: {origin_url})\n")
                else:
                    f.write("No se encontraron disclosures.\n")
                f.write("\n")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--subdomains", required=True, help="Archivo con subdominios (uno por línea)")
    parser.add_argument("-o", "--output", default="disclosures.txt", help="Archivo de salida (report)")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Número de hilos de ejecución")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Profundidad BFS interna")
    args = parser.parse_args()

    ds = DisclosureSearch(
        subdomains_file=args.subdomains,
        output_file=args.output,
        workers=args.workers,
        max_depth=args.depth
    )
    ds.run()
