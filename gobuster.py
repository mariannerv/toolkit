import sys
import argparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Função auxiliar para ler os ficheiros
def read_file(word_list):
    with open(word_list, "r") as f:
        return [line.strip() for line in f]

# Função que faz o request
def check_url(domain, word):
    url = f"http://{domain}/{word}"
    good_codes = [200, 403, 301, 308]
    try:
        res = requests.get(url, timeout=1)
        if res.status_code in good_codes:
            print(f"[+] [{res.status_code}] -> /{word}")
            return url
    except requests.RequestException:
        pass
    return None

# Função principal com ThreadPool
def gobusterwannabe(domain, wordlist, max_workers=5):
    lista = read_file(wordlist)
    found = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check_url, domain, word) for word in lista]

        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    print("All directories have been tested. Exiting...")
    return found


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gobuster wannabe XPTO very nice")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("wordlist", help="File with words to try")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads to use (default: 5)")

    args = parser.parse_args()
    gobusterwannabe(args.domain, args.wordlist, max_workers=args.threads)
