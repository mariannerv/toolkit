# Network Security Toolkit

This repository contains a collection of Python scripts for various network security tasks including port scanning, subdomain enumeration, header fuzzing, and LFI vulnerability detection.

## Scripts Overview

### 1. `fuzzer.py` - HTTP Header Fuzzer
**Purpose**: Tests web applications by sending various HTTP headers to identify potential vulnerabilities or misconfigurations.

**Usage**:
```bash
python3 fuzzer.py -t example.com
```

**Example Output**:
```
Using HTTPS protocol for example.com...

[+] [200] - X-Forwarded-For: 127.0.0.1 -> https://example.com
[+] [403] - X-Powered-By: malicious_value_1 -> https://example.com
```

### 2. `gobuster.py` - Directory Bruteforcer
**Purpose**: Enumerates directories and files on a web server using a wordlist.

**Usage**:
```bash
python3 gobuster.py example.com wordlist.txt --threads 20
```

**Example Output**:
```
[+] [200] -> /admin
[+] [301] -> /images
[+] [403] -> /config
All directories have been tested. Exiting...
```

### 3. `lfi.py` and `lfi_v2.py` - Local File Inclusion Scanner
**Purpose**: Tests for LFI vulnerabilities with various payloads.

**Basic Usage**:
```bash
python3 lfi.py -t "http://example.com/page.php?file=" -w lfi_wordlist.txt -l 100
```

**Advanced Usage (v2)**:
```bash
python3 lfi_v2.py -t "http://example.com/page.php?file=" --auto-depth
python3 lfi_v2.py -t "http://example.com/page.php?file=" -w lfi_wordlist.txt -l 100 --threads 30
```

**Example Output**:
```
[+] 200    1024    HIGH            ../../../../etc/passwd
[+] 200    512     MEDIUM          ....//....//....//etc/hosts
```

### 4. `my_nmap.py` - Port Scanner with Banner Grabbing
**Purpose**: Scans for open ports and attempts to grab service banners.

**Usage**:
```bash
python3 my_nmap.py -t 192.168.1.1 -p 20-1000 --threads 50
python3 my_nmap.py -t 10.0.0.0/24 -p 80,443,8080
```

**Example Output**:
```
[192.168.1.1] [OPEN] 22
    └─ Port 22 Banner: SSH-2.0-OpenSSH_7.9p1
[192.168.1.1] [OPEN] 80
    └─ Port 80 Banner: HTTP/1.1 200 OK...
```

### 5. `ping.py` - ICMP Ping Scanner
**Purpose**: Scans a network range for live hosts using ICMP ping.

**Usage**:
```bash
python3 ping.py 10.0.0.0/24 --timeout 0.5
python3 ping.py 192.168.1.100 --quiet
```

**Example Output**:
```
[ALIVE] 10.0.0.1
[ALIVE] 10.0.0.15
[NO REPLY] 10.0.0.2

Scan complete.
Live hosts found: 2
```

### 6. `subdomain_finder.py` - Subdomain Enumerator
**Purpose**: Discovers subdomains through DNS resolution.

**Usage**:
```bash
python3 subdomain_finder.py example.com subdomains.txt --threads 30
```

**Example Output**:
```
[+] Found: admin.example.com -> 192.168.1.10
[+] Found: mail.example.com -> 192.168.1.20, 192.168.1.21
Subdomain scan complete.
```

## Requirements
- Python 3.x
- Required packages:
  ```
  pip install requests scapy dnspython colorama
  ```

## Notes
- Use these tools only on systems you have permission to test
- Some scripts may require root privileges for certain operations
- Adjust thread counts based on your network and system capabilities
- Wordlists are not included - use common security wordlists like SecLists

Happy ethical hacking!
