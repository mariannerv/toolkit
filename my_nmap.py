import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import ipaddress

common_ports = {
    20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP Server", 68: "DHCP Client", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    465: "SMTPS", 993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP Alternative", 8443: "HTTPS Alternative", 27017: "MongoDB",
}

port_banners = {
    21: None,
    22: None,
    25: None,
    80: b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
}

print_lock = Lock()

def scan_port(host, port, open_ports, closed_ports):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            res = s.connect_ex((host, port))
            if res == 0:
                with print_lock:
                    open_ports.append(port)
                    print(f"[{host}] [OPEN] {port}")
            else:
                with print_lock:
                    closed_ports.append(port)
    except:
        pass

def grab_banner(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((host, port))
            if port_banners[port]:  
                s.sendall(port_banners[port])
            banner = s.recv(1024).decode(errors="ignore").strip()
            if banner:
                print(f"    └─ Port {port} Banner: {banner}")
    except:
        pass

def scan_host(host, start_port, end_port, max_threads):
    open_ports = []
    closed_ports = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(scan_port, host, port, open_ports, closed_ports)
                   for port in range(start_port, end_port + 1)]
        for _ in as_completed(futures):
            pass

    
    if open_ports:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(grab_banner, host, port) for port in open_ports if port in port_banners]
            for _ in as_completed(futures):
                pass

def main(target_network, start_port, end_port, max_threads):
    print("Scanning...")
    try:
        hosts = [str(ip) for ip in ipaddress.ip_network(target_network).hosts()]
    except ValueError:
        hosts = [target_network]

    for host in hosts:
        scan_host(host, start_port, end_port, max_threads)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Minimalist port scanner with banner grabbing")
    parser.add_argument("-t", "--target", required=True, help="Target IP or CIDR (e.g. 10.0.9.0/24)")
    parser.add_argument("-p", "--ports", default="20-100", help="Port range (e.g. 20-80)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    args = parser.parse_args()

    start_port, end_port = map(int, args.ports.split("-"))
    try:
        main(args.target, start_port, end_port, args.threads)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting gracefully.")
        exit
