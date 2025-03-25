import os
import requests
import time
import subprocess
import json
import asyncio
import shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from shodan import Shodan
from censys.search import CensysCertificates
from datetime import datetime
from tqdm import tqdm
from colorama import Fore, Style, init
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

# تهيئة الألوان
init(autoreset=True)

# شعار الأداة
LOGO = f"""
{Fore.CYAN}
            _____   __  __     _____   _____ ____ _______ _____  ________   __
      /\   / _ \ \ / /  \ \   / / _ \ / ____|___ |__   __|  __ \|  ____\ \ / /
     /  \ | | | \ V _____\ \_/ | | | | (___   __) | | |  | |__) | |__   \ V / 
    / /\ \| | | |> |______\   /| | | |\___ \ |__ <  | |  |  _  /|  __|   > <  
   / ____ | |_| / . \      | | | |_| |____) |___) | | |  | | \ \| |____ / . \ 
  /_/    \_\___/_/ \_\     |_|  \___/|_____/|____/  |_|  |_|  \_|______/_/ \_\
{Style.RESET_ALL}
"""

print(LOGO)

def install_requirements():
    print(f"{Fore.YELLOW}[+] جاري تثبيت المتطلبات...{Style.RESET_ALL}")
    try:
        subprocess.run(["pip", "install", "-r", "requirements.txt"], check=True)
        print(f"{Fore.GREEN}[+] تم تثبيت جميع المتطلبات بنجاح!{Style.RESET_ALL}")
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[-] فشل تثبيت المتطلبات! تأكد من وجود requirements.txt.{Style.RESET_ALL}")

install_requirements()

def check_and_install_tool(tool_name, install_cmd):
    if shutil.which(tool_name):
        print(f"{Fore.GREEN}[+] الأداة {tool_name} مثبتة بالفعل.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[-] الأداة {tool_name} غير مثبتة، يتم التثبيت الآن...{Style.RESET_ALL}")
        subprocess.run(install_cmd, shell=True)
        print(f"{Fore.GREEN}[+] تم تثبيت {tool_name} بنجاح.{Style.RESET_ALL}")

def setup_tools():
    tools = {
        "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "amass": "sudo apt install -y amass",
        "nmap": "sudo apt install -y nmap",
        "assetfinder": "go install -v github.com/tomnomnom/assetfinder@latest",
        "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "waybackurls": "go install -v github.com/tomnomnom/waybackurls@latest"
    }
    with Progress(SpinnerColumn(), TextColumn("{task.description}")) as progress:
        task = progress.add_task("[cyan]إعداد الأدوات...", total=len(tools))
        with ThreadPoolExecutor() as executor:
            for tool, cmd in tools.items():
                check_and_install_tool(tool, cmd)
                progress.update(task, advance=1)

def get_telegram_username():
    return input(f"\n{Fore.YELLOW}[+] أدخل اسم المستخدم في تيليجرام: @{Style.RESET_ALL}")

def send_telegram_message(user, message):
    print(f"{Fore.BLUE}[+] إرسال رسالة إلى @{user}: {message}{Style.RESET_ALL}")

def run_command_async(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    output = [line.strip() for line in process.stdout if line.strip()]
    process.wait()
    return output

def fetch_subdomains(domain):
    print(f"{Fore.CYAN}[*] البحث عن النطاقات الفرعية لـ {domain}...{Style.RESET_ALL}")
    tools = {
        "subfinder": ["subfinder", "-d", domain],
        "amass": ["amass", "enum", "-d", domain],
        "assetfinder": ["assetfinder", domain]
    }
    subdomains = set()
    with ThreadPoolExecutor() as executor:
        results = executor.map(run_command_async, tools.values())
    for res in results:
        subdomains.update(res)
    return list(subdomains)

def check_alive_domains(subdomains):
    print(f"{Fore.CYAN}[*] التحقق من النطاقات الحية باستخدام httpx...{Style.RESET_ALL}")
    if not subdomains:
        return []
    return run_command_async(["httpx", "-silent"] + subdomains)

def fetch_wayback_urls(domain):
    print(f"{Fore.CYAN}[*] جلب روابط Wayback Machine لـ {domain}...{Style.RESET_ALL}")
    return run_command_async(["waybackurls", domain])

def run_nmap_scan(domain):
    print(f"{Fore.CYAN}[*] تشغيل فحص Nmap لـ {domain}...{Style.RESET_ALL}")
    return run_command_async(["nmap", "-Pn", "-p", "1-65535", domain])

def save_results(results):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_dir = Path("results")
    try:
        output_dir.mkdir(exist_ok=True)
    except Exception as e:
        print(f"{Fore.RED}[-] خطأ أثناء إنشاء المجلد: {e}{Style.RESET_ALL}")
        return
    filename_txt = output_dir / f"scan_results_{timestamp}.txt"
    filename_json = output_dir / f"scan_results_{timestamp}.json"
    filename_txt.write_text(json.dumps(results, indent=4))
    filename_json.write_text(json.dumps(results, indent=4))
    print(f"{Fore.GREEN}[+] تم حفظ النتائج في {filename_txt} و {filename_json}{Style.RESET_ALL}")

async def main():
    setup_tools()
    telegram_user = get_telegram_username()
    domains = input(f"\n{Fore.YELLOW}[+] أدخل النطاقات المستهدفة (مفصولة بفاصلة): {Style.RESET_ALL}").split(',')
    results = {}
    for domain in tqdm(domains, desc="Scanning Domains"):
        domain = domain.strip()
        subdomains = await asyncio.to_thread(fetch_subdomains, domain)
        alive_domains = await asyncio.to_thread(check_alive_domains, subdomains)
        wayback_urls = await asyncio.to_thread(fetch_wayback_urls, domain)
        nmap_scan = await asyncio.to_thread(run_nmap_scan, domain)
        results[domain] = {"subdomains": subdomains, "alive": alive_domains, "wayback_urls": wayback_urls, "nmap_scan": nmap_scan}
        send_telegram_message(telegram_user, f"تم الانتهاء من فحص {domain}")
    save_results(results)

if __name__ == "__main__":
    asyncio.run(main())
