from scapy.all import IP, ICMP, sr1
import argparse
import ipaddress
import time

def scan(network, timeout=1, verbose=True):
    ip_list = [str(ip) for ip in ipaddress.ip_network(network).hosts()]
    live_hosts = []

    print(f"Scanning {len(ip_list)} hosts...")

    for ip in ip_list:
        pkt = IP(dst=ip)/ICMP()
        reply = sr1(pkt, timeout=timeout, verbose=0)

        if reply:
            print(f"[ALIVE] {ip}")
            live_hosts.append(ip)
        elif verbose:
            print(f"[NO REPLY] {ip}")

    print("\nScan complete.")
    print(f"Live hosts found: {len(live_hosts)}")

    return live_hosts

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple ICMP ping scanner (like nmap -sn)")
    parser.add_argument("network", help="Network in CIDR format (e.g. 10.0.9.0/24)")
    parser.add_argument("--timeout", type=float, default=1, help="Timeout per host (default: 1 second)")
    parser.add_argument("--quiet", action="store_true", help="Suppress non-reply output")
    args = parser.parse_args()

    scan(args.network, timeout=args.timeout, verbose=not args.quiet)
