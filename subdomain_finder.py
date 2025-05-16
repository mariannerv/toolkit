import argparse
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed

# Read subdomains from a file
def read_file(wordlist):
    with open(wordlist, "r") as f:
        return [line.strip() for line in f]

# Check if subdomain resolves
def check_subdomain(sub, domain):
    full_domain = f"{sub}.{domain}"
    try:
        answers = dns.resolver.resolve(full_domain, 'A')
        ips = [rdata.address for rdata in answers]
        print(f"[+] Found: {full_domain} -> {', '.join(ips)}")
        return (full_domain, ips)
    except dns.resolver.NXDOMAIN:
        pass  # Doesn't exist
    except dns.resolver.NoAnswer:
        pass  # Exists, but no A record
    except dns.resolver.Timeout:
        pass  # DNS timeout
    except Exception as e:
        print(f"[!] Error checking {full_domain}: {e}")
    return None

# Main function
def subdomain_enum(domain, wordlist, max_workers=10):
    print("Scanning....")
    subs = read_file(wordlist)
    found = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check_subdomain, sub, domain) for sub in subs]

        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    print("Subdomain scan complete.")
    return found

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Subdomain enum wannabe very nice")
    parser.add_argument("domain", help="Target domain (e.g. target.com)")
    parser.add_argument("wordlist", help="File with possible subdomains (e.g. admin, dev, mail)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads to use (default: 10)")
    args = parser.parse_args()

    subdomain_enum(args.domain, args.wordlist, max_workers=args.threads)
