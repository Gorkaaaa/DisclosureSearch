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

class DisclosureSearch:
    def __init__(self, subdomains_file, output_file, workers=10, max_depth=2):
        self.subdomains_file = subdomains_file
        self.output_file = output_file
        self.workers = workers
        self.max_depth = max_depth
        self.request_timeout = 15

        # GRAN LISTA DE REGEX
        # Se añaden todo tipo de patrones: credenciales, IPs, hashes, logs, claves de
        # terceros, etc. Ajustar y ampliar según necesidad, sabiendo que pueden haber
        # falsos positivos.
        self.regexes = {
            # AWS
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key": r"(?i)aws(.{0,20})?secret(.{0,20})?=\s*[0-9a-zA-Z/+]{40}",

            # Google & Firebase
            "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
            "Firebase URL": r"(https?://[a-z0-9-]+\.firebaseio\.com)",

            # Azure
            "Azure Storage Key": r"(?i)(AccountKey|SharedKey)\s*=\s*[A-Za-z0-9+/=]{40,}",
            
            # Slack
            "Slack Token": r"xox[baprs]-[0-9]{12,}-[0-9]{12,}-[a-zA-Z0-9]{24,}",
            
            # JWT
            "JWT": r"ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",

            # Bearer
            "Bearer Token": r"(?i)bearer\s+[a-zA-Z0-9_\-\.=]+",

            # Basic Auth
            "Basic Auth Header": r"(?i)authorization:\s*Basic\s+[a-zA-Z0-9=]+",

            # API Keys (genéricas)
            "API Key (Generic)": r"(?i)(api_key|apiKey|api-key|apikey)\s*[=:]\s*[A-Za-z0-9_\-]+",
            
            # SSH / PRIVATE KEY
            "SSH Private Key": r"-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----",
            "SSH RSA Key": r"-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----",

            # Emails
            "Email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",

            # Internal IPs
            "Internal IP": r"(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})",

            # Credenciales en log / password
            "Possible Password in Log": r"(password|passwd|pwd|pass)\s*=\s*['\"]?([A-Za-z0-9@#$%^&+=!_-]+)['\"]?",
            
            # Hashes
            "MD5 Hash": r"\b[a-f0-9]{32}\b",
            "SHA1 Hash": r"\b[a-f0-9]{40}\b",
            "SHA256 Hash": r"\b[A-Fa-f0-9]{64}\b",
            "Bcrypt Hash": r"\$2[aby]\$.{56}",
            
            # Tokens en general (variaciones)
            "Generic Token": r"(token|csrf_token|xsrf-token|auth_token|session_token)\s*[:=]\s*[A-Za-z0-9_\-]+",
        }

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
                                   ░                                             

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
        for name, pattern in self.regexes.items():
            matches = re.findall(pattern, text)
            for m in matches:
                if isinstance(m, tuple):
                    m = " ".join(m)
                findings.append((name, m))
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
                            self.color_print(
                                f"[CRAWL] {current_url} => {len(found_links)} enlaces (nivel {depth+1})",
                                Fore.YELLOW
                            )
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
    parser.add_argument("-s", "--subdomains", required=True, help="Archivo con subdominios")
    parser.add_argument("-o", "--output", default="disclosures.txt", help="Archivo de salida")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Hilos de ejecución")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Profundidad BFS interna")
    args = parser.parse_args()

    ds = DisclosureSearch(
        subdomains_file=args.subdomains,
        output_file=args.output,
        workers=args.workers,
        max_depth=args.depth
    )
    ds.run()
