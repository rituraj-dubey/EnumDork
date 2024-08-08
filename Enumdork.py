import requests
import socket
from bs4 import BeautifulSoup
import termcolor
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from concurrent.futures import ThreadPoolExecutor
import whois
import random
from time import sleep
import dns.resolver
from Wappalyzer import Wappalyzer, WebPage

# Colour Function
def color(object, color):
    return termcolor.colored((object), color)

# Function to retrieve HTTP headers
def retrieve_http_headers(url):
    req_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"}
    response = requests.get(url, headers=req_headers)
    headers = response.headers
    print(color("\nHTTP Headers:", "green"), headers)
    print()
    return headers

# Function for DNS lookup
def dnslookup(domain):
    domain = domain.split("//")[1]
    print(color("[+] DNS Lookup:", 'green'))
    record_types = ['A', 'AAAA', 'MX', 'NS', 'CNAME', 'TXT', 'SOA']
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            print(color(f"\n{record_type} Records:", 'blue'))
            for rdata in answers:
                print(rdata.to_text())
        except dns.resolver.NoAnswer:
            print(color(f"\n{record_type} Records: No answer", 'yellow'))
        except dns.resolver.NXDOMAIN:
            print(
                color(f"\n{record_type} Records: Domain does not exist", 'red'))
        except dns.resolver.Timeout:
            print(f"\n{record_type} Records: Query timed out")
        except Exception as e:
            print(f"\n{record_type} Records: An error occurred: {e}")
    print()

# Function for Whoislookup
def whoislookup(domain):
    w = whois.whois(domain)
    print(color("[+] WHOIS Lookup: ", 'green'))
    print(w)
    print()

# Function to identify web server software
def identify_web_server(headers):
    server = headers.get('Server', 'Unknown')
    print(color("Web Server:", "green"), server)
    print()
    return server

# Function to resolve IP address
def resolve_ip_address(url):
    domain = url.split('//')[-1].split('/')[0]
    ip_address = socket.gethostbyname(domain)
    print(color("IP Address:", "green"), ip_address)
    print()
    return ip_address

# Function to retrieve and parse sitemap
def retrieve_sitemap(url):
    sitemap_url = url + '/sitemap.xml'
    response = requests.get(sitemap_url)
    if response.status_code == 200:
        print(color("Sitemap found!", "blue"))
        soup = BeautifulSoup(response.content, 'xml')
        for loc in soup.find_all('loc'):
            print(color("Sitemap URL:", "green"), loc.text)
        print()


# Function to retrieve and parse robots.txt
def retrieve_robots_txt(url):
    robots_url = url + '/robots.txt'
    response = requests.get(robots_url)
    if response.status_code == 200:
        print(color("\nRobots.txt found!", "blue"))
        print()
        print(response.text)


# Function to perform technology profiling using Wappalyzer
def technology_profiling(url):
    wappalyzer = Wappalyzer.latest()
    webpage = WebPage.new_from_url(url)
    technologies = wappalyzer.analyze_with_versions_and_categories(webpage)
    print(color("\nTechnologies used:", "green"), technologies)
    print()
    return technologies

# Helper functions for dir_enum

def read_wordlist(file_path):
    with open(file_path, 'r') as file:
        words = file.read().splitlines()
    return words

def check_directory(url, directory):
    if url.startswith("http://"):
        url =url
    elif not url.startswith('https://'):
        url = "https://"+url
    full_url = f"{url}/{directory}/"
    try:
        response = requests.get(full_url)
        status_code = response.status_code

        if status_code == 200:
            if not response.text.title().__contains__('404'):
                print(color(f"Found: {full_url}", 'green'))
                found[0] += 1
        elif status_code == 301:
            print(f"Moved Permanently (301): {full_url} -> {response.headers.get('Location')}")
        elif status_code == 302:
            print(color(f"Found (302): {full_url} -> {response.headers.get('Location')}", 'blue'))

    except requests.RequestException as e:
        print(f"Error accessing {full_url}: {e}")

# Function to create browser instance for Dorking
def create_browser():
    user_agents = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.2420.81',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:124.0) Gecko/20100101 Firefox/124.0',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0',
                   'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
                   'Mozilla/5.0 (X11; Linux i686; rv:124.0) Gecko/20100101 Firefox/124.0',
                   'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; en) Opera 10.62',
                   'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; fr) Opera 11.00',
                   'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.2; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)']
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument(f'User-Agent={random.choice(user_agents)}')
    browser = webdriver.Chrome(options=chrome_options)
    return browser

# Function to perform google search using webdriver browser instance
def perform_google_search(query, target):
    browser = create_browser()
    delay = random.uniform(2, 5) # random time delay to induce human behaviour (prevents anti-bot mechnasim)
    sleep(delay)
    browser.get(f"https://www.google.com/search?q=site:{target} {query}")
    sleep(delay) # Bypass anti-bot mechansism
    page_source = browser.page_source
    browser.quit()
    return page_source

# Parsing Dorked HTML page source results
def parse_search_results(html):
    soup = BeautifulSoup(html, 'html.parser')
    for item in soup.find_all('div', class_='yuRUbf'):
        link = item.find('a', href=True)
        if link:
            print(color("[+] "+link.get('href'), 'blue'))
            found[2] += 1

# Function to load Dork files
def generate_google_dork_queries():
    with open("./dorks/sensitivefile_dorks.txt", 'r') as sensitive_dork_file:
        sensitive_files = sensitive_dork_file.read().splitlines()
    with open("./dorks/login_page_dorks.txt", 'r') as login_dork_file:
        login_pages = login_dork_file.read().splitlines()
    with open("./dorks/directory_traversal_dorks.txt", 'r') as directory_dork_file:
        directory_imp = directory_dork_file.read().splitlines()
    return sensitive_files,login_pages,directory_imp

# Main functions

def basic_enum(target_url):
    if target_url.startswith("http://"):
        target_url = target_url
    elif not target_url.startswith('https://'):
        target_url = "https://"+target_url
    headers = retrieve_http_headers(target_url)
    identify_web_server(headers)
    resolve_ip_address(target_url)
    retrieve_sitemap(target_url)
    retrieve_robots_txt(target_url)
    technology_profiling(target_url)
    dnslookup(target_url)
    whoislookup(target_url)
    start()


def dir_enum(target):
    print(color("\nSelect Wordlist:", 'green'))
    print(color(
        """
            1. Dirbuster-list-2.3-medium.txt
            2. Dirbuster-list-2.3-small.txt
            3. Dirb Common.txt
            4. Dirb Big.txt
            5. Dirb Small.txt""", 'blue')
    )
    wordlist = int(input("Enter the Selection : "))
    if wordlist == 1:
        directories = read_wordlist(
            "./wordlists/directory-list-2.3-medium.txt")
    elif wordlist == 2:
        directories = read_wordlist(
            "./wordlists/directory-list-2.3-small.txt")
    elif wordlist == 3:
        directories = read_wordlist("./wordlists/common.txt")
    elif wordlist == 4:
        directories = read_wordlist("./wordlists/big.txt")
    elif wordlist == 5:
        directories = read_wordlist("./wordlists/small.txt")
    else:
        print(color("[-] Invalid Option, Please select from the Options", 'red'))
        dir_enum(target)

    with ThreadPoolExecutor(max_workers=10) as executor:
        for directory in directories:
            executor.submit(check_directory, target, directory)
    if found[0]==0:
        print(color("[-] No Hidden Directory Found", 'red'))
    start()

def dork_em(target):
    if target.startswith("https://") or target.startswith("http://"):
        target = target.replace("https://","")
        target = target.replace("http://","")
    sens_file,login_pages,imp_directory = generate_google_dork_queries()

    print(termcolor.colored("\n[+] Executing Google Dorks for Senistive file disclosure", 'green', attrs=['bold']))
    for query in sens_file:
        print(color(f"\nDork:site:{target} {query}", 'magenta'))
        print("----------------------------------------------------")
        html = perform_google_search(query, target)
        parse_search_results(html)
        if found[2]==0:
            print(color("[-] No Links found for that dork", 'red'))
        found[2] = 0
        sleep(2)

    print(termcolor.colored("\n[+] Executing Google Dorks for Sensitive Portals", 'green', attrs=['bold']))
    for query in login_pages:

        print(color(f"\nDork:site:{target} {query}", 'magenta'))
        print("----------------------------------------------------")
        html = perform_google_search(query, target)
        parse_search_results(html)
        if found[2]==0:
            print(color("[-] No Links found for that dork", 'red'))
        found[2] = 0
        sleep(2)

    print(termcolor.colored("\n[+] Executing Google Dorks for Senisitive Directories", 'green', attrs=['bold']))
    for query in imp_directory:
        print(color(f"\nDork:site:{target} {query}", 'magenta'))
        print("----------------------------------------------------")
        html = perform_google_search(query, target)
        parse_search_results(html)
        if found[2]==0:
            print(color("[-] No Links found for that dork", 'red'))
        found[2] = 0
        sleep(2)
    print()
    start()


if __name__ == "__main__":
    global found #flag variable
    found = [0,1,0]
    print(termcolor.colored("""
   ____                ___           __  
  / __/__  __ ____ _  / _ \___  ____/ /__
 / _// _ \/ // /  ' \/ // / _ \/ __/  '_/
/___/_//_/\_,_/_/_/_/____/\___/_/ /_/\_\ 
                          --by Rituraj
          """, 'red', attrs=['bold']))
    def start():
        print(color(f"""
Scan #{found[1]}
========================================================================================
                    """, 'magenta'))
        print("Select Mode:")
        print(
            color("""
    1. Basic Enumeration (Http headers, Dns, whois, Wappalyzer, sitemap.xml, robots.txt)
    2. Directory Enumeration
    3. Google Dorking 
    4. Quit
    """, 'blue')
        )
        mode = int(input(color("Select Mode: ", 'green')))
        if mode == 1:
            print(termcolor.colored(
                "\n[+] Basic Enumeration Mode", 'green', attrs=['bold', 'underline']))
            target = input("\nEnter Target: ")
            found[1] += 1
            basic_enum(target)
        elif mode == 2:
            print(termcolor.colored(
                "\n[+] Directory Enumeration Mode", 'green', attrs=['bold', 'underline']))
            target = input("\nEnter the Target Url: ")
            found[1] += 1
            dir_enum(target)
        elif mode == 3:
            print(termcolor.colored("\n[+] Google Dorking",
                'green', attrs=['bold', 'underline']))
            target = input("\nEnter Target: ")
            found[1] += 1
            dork_em(target)
        elif mode == 4:
            print(color("Quitting...", 'red'))
            print(color("Bye..\U0001F44B", 'blue'))
            pass

    start()
