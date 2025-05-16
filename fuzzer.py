import requests
import argparse
import threading


headers_list = [
    "X-Originating-IP", "X-Forwarded-For", "X-Custom-Test", "X-Powered-By", "X-Server",
    "X-ASP.NET-Version", "X-Content-Duration", "X-Debug-Mode", "X-Docker-Container", "X-Node-Id",
    "X-App-Name", "X-Real-IP"
]

header_values = [
    "127.0.0.1", "192.168.0.1", "10.0.0.1", "localhost", "8.8.8.8",
    "malicious_value_1", "ilikepotatosalot", "rosesarenotred", "custom_value_2"
]


def fuzz_header(domain, header, value, protocol):
    url = f"{protocol}://{domain}"  
    headers = {header: value}  
    try:
        response = requests.get(url, headers=headers, timeout=3)
        if response.status_code in [200, 301, 302, 403]: 
            print(f"[+] [{response.status_code}] - {header}: {value} -> {url}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error with {header}: {value} -> {e}")


def check_protocol(domain):
    # Try HTTPS first
    try:
        response = requests.get(f"https://{domain}", timeout=3)
        if response.status_code == 200:
            return "https"  
    except requests.exceptions.RequestException:
        pass  

    return "http"


def run_fuzzing(domain, protocol):
    threads = []
    for header in headers_list:
        for value in header_values:
            thread = threading.Thread(target=fuzz_header, args=(domain, header, value, protocol))
            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join()

def main(domain):
    protocol = check_protocol(domain)
    print(f"Using {protocol.upper()} protocol for {domain}...\n")

    run_fuzzing(domain, protocol)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTPS and HTTP Header Fuzzer with Threading")
    parser.add_argument("-t", "--target", required=True, help="Target domain")
    args = parser.parse_args()

    print(f"Starting fuzzing for {args.target}...\n")
    main(args.target)
