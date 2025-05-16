import requests
import argparse
import os
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

print_lock = threading.Lock()
found_results = False

def check_lfi(base_url, payload, min_length):
    """Check a single payload against the target"""
    global found_results
    try:
        full_url = f"{base_url}{payload}"
        
        # Disable redirects and set timeout
        response = requests.get(
            full_url,
            timeout=5,
            allow_redirects=False,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        
        # Skip if we got redirected (3xx status)
        if 300 <= response.status_code < 400:
            return False
            
        # Check for 200/403 with minimum length
        if response.status_code in [200, 403] and len(response.text) >= min_length:
            # Basic check to verify this isn't just a redirect page
            if "location:" not in response.text.lower():
                with print_lock:
                    print(f"[+] {response.status_code:3} {len(response.text):6} Ch  {payload}")
                    found_results = True
                return True
        return False
    except Exception as e:
        return False

def lfi_scan(base_url, wordlist_file, min_length, threads=20):
    """Run the threaded LFI scan"""
    global found_results
    
    if not os.path.exists(wordlist_file):
        print(f"[!] Wordlist file {wordlist_file} not found.")
        return

    try:
        with open(wordlist_file, 'r') as f:
            payloads = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        print(f"[!] Error reading the wordlist: {e}")
        return

    print(f"\n[+] Starting threaded LFI scan ({threads} threads)")
    print(f"[+] Target: {base_url}")
    print(f"[+] Minimum response length: {min_length} chars")
    print(f"[+] Ignoring redirects (3xx status codes)\n")
    print("Code  Length  Payload")
    print("----  ------  -------")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(check_lfi, base_url, payload, min_length) 
                 for payload in payloads]
        
        for _ in as_completed(futures):
            pass  # Results are printed within check_lfi

    if not found_results:
        print("[-] No valid results found (after filtering redirects)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LFI Scanner - Redirect-Aware")
    parser.add_argument("-t", "--target", required=True, help="Target URL with parameter")
    parser.add_argument("-w", "--wordlist", default="/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt", help="Path to LFI wordlist")
    parser.add_argument("-l", "--length", type=int, required=True, help="Minimum response length to consider")
    parser.add_argument("--threads", type=int, default=20, help="Number of threads (default: 20)")

    args = parser.parse_args()

    if "=" not in args.target:
        print("[!] Target URL should include parameter (e.g., http://example.com/page=)")
        exit()

    lfi_scan(args.target, args.wordlist, args.length, args.threads)
    print("\n[+] Scan completed")