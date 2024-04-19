# Importing necessary libraries
import argparse
import socket
import requests
import json
import threading

# Introduction to Cyb3rVolt3x
def intro():
    print("""  _________.__                .___                  ___________             
 /   _____/|  |__ _____     __| _/______  _  _______\_   _____/__.__. ____  
 \_____  \ |  |  \\__  \   / __ |/  _ \ \/ \/ /  ___/|    __)<   |  |/ __ \ 
 /        \|   Y  \/ __ \_/ /_/ (  <_> )     /\___ \ |        \___  \  ___/ 
/_______  /|___|  (____  /\____ |\____/ \/\_//____  >_______  / ____|\___  >
        \/      \/     \/      \/                 \/        \/\/         \/ 
    Welcome to Cyb3rVolt3x - Your Ultimate Cybersecurity Arsenal!
    
    Developer: Syed Zada Abrar
    Code Name: Cyb3rVolt3x
    Community: AndraxHub
    
    Prepare to delve into the darkest corners of the digital realm as you harness the power of Cyb3rVolt3x for your bug hunting endeavors. With its advanced tools and malevolent capabilities, no target is safe from your probing gaze.
    
    Remember, with great power comes great chaos. Use Cyb3rVolt3x wisely, and may the digital shadows be ever in your favor.
    """)

# Insert this line before initiating information gathering
intro()

# Global variable to store found subdomains
found_subdomains = []

# Function to perform DNS lookup
def dns_lookup(target):
    try:
        ip_address = socket.gethostbyname(target)
        print(f"[+] DNS Lookup: {target} resolves to {ip_address}")
    except socket.gaierror:
        print(f"[-] DNS Lookup failed for {target}")

# Function to discover subdomains using bruteforce
def bruteforce_subdomains(target, wordlist):
    global found_subdomains
    with open(wordlist, 'r') as wordlist_file:
        for word in wordlist_file:
            subdomain = word.strip() + "." + target
            try:
                socket.inet_aton(subdomain)
            except socket.error:
                continue
            dns_lookup(subdomain)
            found_subdomains.append(subdomain)

# Function to perform port scanning
def port_scan(target, port_range):
    for port in range(port_range[0], port_range[1] + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"[+] Open port: {target}:{port}")
        sock.close()

# Function to perform Whois lookup
def whois_lookup(target):
    whois_url = "https://api.whois.com/whois/" + target
    response = requests.get(whois_url)
    if response.status_code == 200:
        whois_data = json.loads(response.text)
        print(f"[+] WHOIS Lookup for {target}:\n{json.dumps(whois_data, indent=2)}")
    else:
        print(f"[-] WHOIS Lookup failed for {target}")

# Function to discover social media profiles
def social_media_scan(target):
    social_media_urls = {
        "facebook": "https://www.facebook.com/" + target,
        "twitter": "https://twitter.com/" + target,
        "instagram": "https://www.instagram.com/" + target,
        "linkedin": "https://www.linkedin.com/company/" + target
    }
    for platform, url in social_media_urls.items():
        response = requests.get(url)
        if response.status_code == 200:
            print(f"[+] {platform} profile found: {url}")
        else:
            print(f"[-] {platform} profile not found")

# Function to check for password leaks
def password_leak_check(target):
    params = {"domain": target}
    response = requests.get("https://api.pwnedpasswords.com/range", params=params)
    if response.status_code == 200:
        data = response.text.splitlines()
        leaked_hashes = [hash for hash in data if hash.startswith(target.lower())]
        if leaked_hashes:
            print(f"[!] Leaked passwords found for {target} domain:")
            for hash in leaked_hashes:
                print(f"  - {hash.split(':')[1]}")
        else:
            print(f"[-] No leaked passwords found for {target} domain")
    else:
        print("[!] Failed to retrieve password leak data")

# Function to initiate all information gathering modules
def run_information_gathering(target, wordlist, port_range):
    global found_subdomains
    found_subdomains = []

    print(f"\n[+] Initiating information gathering for {target}")

    # Start thread for bruteforce subdomain discovery
    t1 = threading.Thread(target=bruteforce_subdomains, args=(target, wordlist))
    t1.start()

    # Perform DNS lookup for the target domain
    dns_lookup(target)

    # Perform port scanning
    port_scan(target, port_range)

    # Perform Whois lookup
    whois_lookup(target)

    # Discover social media profiles
    social_media_scan(target)

    # Check for password leaks
    password_leak_check(target)

    # Wait for bruteforce subdomain discovery thread to finish
    t1.join()

    # Print discovered subdomains
    if found_subdomains:
        print(f"[+] Discovered subdomains for {target}:")
        for subdomain in found_subdomains:
            print(f"  - {subdomain}")
    else:
        print(f"[-] No subdomains discovered for {target}")

    print("\n[+] Information gathering completed")

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Shadow\'s Eye - Information Gathering Tool')
parser.add_argument('target', help='Target domain or IP address')
parser.add_argument('--wordlist', default='subdomains.txt', help='Wordlist for bruteforce subdomain discovery')
parser.add_argument('--ports', default='1-1000', help='Port range for scanning (format: start-end)')
args = parser.parse_args()

target = args.target
wordlist = args.wordlist
port_range = list(map(int, args.ports.split('-')))

# Initiate information gathering
run_information_gathering(target, wordlist, port_range)
