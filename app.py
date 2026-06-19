import os, sys, time, json, random, socket, threading, asyncio, subprocess, re, signal, atexit, traceback
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Import authentication functions from JwtGen
from JwtGen import (
    GeNeRaTeAccEss, EncRypTMajoRLoGin, MajorLogin, DecRypTMajoRLoGin,
    GetLoginData, DecRypTLoGinDaTa, xAuThSTarTuP
)

# ========== Global data ==========
connected_clients = {}          # uid -> client object
connected_clients_lock = threading.Lock()

# ====== SPAM QUEUE SYSTEM ======
spam_queue = {}                 # target_uid -> {'start_time': dt, 'duration': min, 'status': 'active'|'paused', 'last_spam': dt}
spam_queue_lock = threading.Lock()

# Generator stats
gen_stats = {
    'success': 0,
    'failed': 0,
    'total': 0,
    'running': False,
    'name_prefix': 'bd',
    'lock': threading.Lock()
}

EREN_FILE = "Eren.txt"
EREN_BACKUP = "Eren_backup.txt"

# KAWSARxGUEST-GEN paths
GEN_FOLDER = "KAWSARxGUEST-GEN"
ACTIVATED_FOLDER = os.path.join(GEN_FOLDER, "ACTIVATED")

# Track already processed accounts
processed_uids = set()

# gen.py subprocess handle
gen_process = None

# ========== Packet functions (FIXED) ==========
def EnC_Uid(H):
    e, H = [], int(H)
    while H:
        e.append((H & 0x7F) | (0x80 if H > 0x7F else 0))
        H >>= 7
    return bytes(e).hex()

def CrEaTe_ProTo(fields):
    def EnC_Vr(N):
        if N < 0:
            return b''
        H = []
        while True:
            b = N & 0x7F
            N >>= 7
            if N:
                b |= 0x80
            H.append(b)
            if not N:
                break
        return bytes(H)
    def CrEaTe_VarianT(field_number, value):
        field_header = (field_number << 3) | 0
        return EnC_Vr(field_header) + EnC_Vr(value)
    def CrEaTe_LenGTh(field_number, value):
        field_header = (field_number << 3) | 2
        encoded_value = value.encode() if isinstance(value, str) else value
        return EnC_Vr(field_header) + EnC_Vr(len(encoded_value)) + encoded_value
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested = CrEaTe_ProTo(value)
            packet.extend(CrEaTe_LenGTh(field, nested))
        elif isinstance(value, int):
            packet.extend(CrEaTe_VarianT(field, value))
        elif isinstance(value, (str, bytes)):
            packet.extend(CrEaTe_LenGTh(field, value))
    return packet

def GeneRaTePk(Pk, N, K, V):
    def EnC_PacKeT(HeX, K, V):
        return AES.new(K, AES.MODE_CBC, V).encrypt(pad(bytes.fromhex(HeX), 16)).hex()
    def DecodE_HeX(H):
        return hex(H)[2:].zfill(2)
    PkEnc = EnC_PacKeT(Pk, K, V)
    _ = DecodE_HeX(len(PkEnc) // 2)
    if len(_) == 2:
        HeadEr = N + "000000"
    elif len(_) == 3:
        HeadEr = N + "00000"
    elif len(_) == 4:
        HeadEr = N + "0000"
    elif len(_) == 5:
        HeadEr = N + "000"
    else:
        HeadEr = N + "000000"
    return bytes.fromhex(HeadEr + _ + PkEnc)

def openroom(K, V):
    fields = {
        1: 2,
        2: {
            1: 1, 2: 15, 3: 5, 4: "[FFFF00]ʙᴅ➺ꫝᴅᴍɪɴ", 5: "1", 6: 12, 7: 1, 8: 1, 9: 1,
            11: 1, 12: 2, 14: 36981056,
            15: {1: "IDC3", 2: 126, 3: "ME"},
            16: "\u0001\u0003\u0004\u0007\t\n\u000b\u0012\u000f\u000e\u0016\u0019\u001a \u001d",
            18: 2368584, 27: 1, 34: "\u0000\u0001", 40: "en", 48: 1,
            49: {1: 21}, 50: {1: 36981056, 2: 2368584, 5: 2}
        }
    }
    return GeneRaTePk(CrEaTe_ProTo(fields).hex(), '0E15', K, V)

def spmroom(K, V, uid):
    fields = {1: 22, 2: {1: int(uid)}}
    return GeneRaTePk(CrEaTe_ProTo(fields).hex(), '0E15', K, V)

# ========== FIXED SPAM SYSTEM ==========
def send_spam_packets(client, target_id, packet_count=10):
    """
    একবার স্প্যাম সেন্ড করবে — ব্যান হলেও কমপক্ষে ১বার ট্রাই করবে
    """
    if not client or not client.key or not client.iv:
        print(f"[❌] {client.uid if client else 'Unknown'}: No key/iv for spam")
        return False
    
    try:
        # Open room packet
        open_pkt = openroom(client.key, client.iv)
        client.online_sock.send(open_pkt)
        print(f"[📤] {client.uid} -> OpenRoom sent to target {target_id}")
        time.sleep(1.5)
        
        # Spam packets
        success_count = 0
        for i in range(packet_count):
            try:
                spam_pkt = spmroom(client.key, client.iv, target_id)
                client.online_sock.send(spam_pkt)
                success_count += 1
                print(f"[💥] {client.uid} -> Spam {i+1}/{packet_count} to {target_id}")
                time.sleep(0.2)
            except Exception as e:
                print(f"[⚠️] {client.uid} -> Spam packet {i+1} failed: {e}")
                # ব্যান হলেও যেগুলো পাঠানো গেছে সেগুলো কাউন্ট করবে
                break
        
        return success_count > 0
        
    except Exception as e:
        print(f"[❌] {client.uid} -> Spam failed completely: {e}")
        client._need_reconnect = True
        return False

def dispatch_spam_for_client(client):
    """
    যখনই ক্লায়েন্ট অনলাইনে আসবে, সক্রিয় সব টার্গেটে স্প্যাম পাঠাবে
    """
    with spam_queue_lock:
        active_targets = {
            uid: info for uid, info in spam_queue.items() 
            if info['status'] == 'active'
        }
    
    if not active_targets:
        print(f"[ℹ️] {client.uid}: No active spam targets in queue")
        return
    
    print(f"[🚀] {client.uid}: Dispatching spam to {len(active_targets)} targets")
    
    for target_id, info in active_targets.items():
        # Duration check
        if info.get('duration'):
            elapsed = (datetime.now() - info['start_time']).total_seconds() / 60
            if elapsed >= info['duration']:
                with spam_queue_lock:
                    if target_id in spam_queue:
                        spam_queue[target_id]['status'] = 'completed'
                print(f"[⏰] Target {target_id} duration expired")
                continue
        
        # Check if recently spammed (avoid duplicate)
        last_spam = info.get('last_spam')
        if last_spam and (datetime.now() - last_spam).total_seconds() < 30:
            continue
        
        # Send spam — ব্যান হলেও কমপক্ষে ১বার ট্রাই
        if client.online_sock and not client._need_reconnect:
            success = send_spam_packets(client, target_id, packet_count=10)
            if success:
                with spam_queue_lock:
                    if target_id in spam_queue:
                        spam_queue[target_id]['last_spam'] = datetime.now()
        else:
            print(f"[⚠️] {client.uid}: Socket not ready for spam")

# ========== FIXED GLOBAL SPAM WORKER ==========
def global_spam_worker():
    """
    প্রতি ৩০ সেকেন্ডে সক্রিয় টার্গেটগুলোতে স্প্যাম পাঠাবে
    """
    print("[🤖] Global Spam Dispatcher started — 30s interval")
    
    while True:
        try:
            with spam_queue_lock:
                # Expired cleanup
                for uid, info in list(spam_queue.items()):
                    if info.get('duration') and info['status'] == 'active':
                        elapsed = (datetime.now() - info['start_time']).total_seconds() / 60
                        if elapsed >= info['duration']:
                            info['status'] = 'completed'
                            print(f"[⏰] Auto-expired: {uid}")
                
                active_targets = {
                    uid: info for uid, info in spam_queue.items() 
                    if info['status'] == 'active'
                }
            
            if not active_targets:
                time.sleep(5)
                continue
            
            with connected_clients_lock:
                clients = list(connected_clients.values())
            
            if not clients:
                print(f"[⏳] No bots online. {len(active_targets)} targets queued. Waiting...")
                time.sleep(10)
                continue
            
            print(f"[🚀] Broadcasting to {len(active_targets)} targets via {len(clients)} bots")
            
            for target_id in active_targets:
                for client in clients:
                    if not client.online_sock or client._need_reconnect:
                        continue
                    
                    # Check last spam time
                    last_spam = active_targets[target_id].get('last_spam')
                    if last_spam and (datetime.now() - last_spam).total_seconds() < 45:
                        continue
                    
                    try:
                        # Send spam — ব্যান হলেও ১বার ট্রাই
                        success = send_spam_packets(client, target_id, packet_count=5)
                        if success:
                            with spam_queue_lock:
                                if target_id in spam_queue:
                                    spam_queue[target_id]['last_spam'] = datetime.now()
                            time.sleep(1)  # Gap between accounts
                    except Exception as e:
                        print(f"[❌] {client.uid} broadcast error: {e}")
                        client._need_reconnect = True
            
            time.sleep(30)  # 30 second interval
            
        except Exception as e:
            print(f"[ERROR] Global spam worker: {e}")
            traceback.print_exc()
            time.sleep(5)

# ========== FIXED ACCOUNT CLIENT ==========
class FF_CLient:
    def __init__(self, uid, password):
        self.uid = uid
        self.password = password
        self.key = None
        self.iv = None
        self.auth_token = None
        self.online_sock = None
        self.running = False
        self._need_reconnect = False
        self._connect()

    def _run_async(self, coro):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def _full_auth(self):
        try:
            open_id, access_token = self._run_async(GeNeRaTeAccEss(self.uid, self.password))
            if not open_id or not access_token:
                print(f"[-] {self.uid} Auth failed: No open_id/access_token")
                return False
            payload = self._run_async(EncRypTMajoRLoGin(open_id, access_token))
            login_res = self._run_async(MajorLogin(payload))
            if not login_res:
                print(f"[-] {self.uid} MajorLogin failed")
                return False
            dec = self._run_async(DecRypTMajoRLoGin(login_res))
            self.key = dec.key
            self.iv = dec.iv
            token = dec.token
            timestamp = dec.timestamp
            account_uid = dec.account_uid
            login_data = self._run_async(GetLoginData(dec.url, payload, token))
            if not login_data:
                print(f"[-] {self.uid} GetLoginData failed")
                return False
            ports = self._run_async(DecRypTLoGinDaTa(login_data))
            online_ip, online_port = ports.Online_IP_Port.split(":")
            self.online_ip = online_ip
            self.online_port = int(online_port)
            self.auth_token = self._run_async(xAuThSTarTuP(
                int(account_uid), token, int(timestamp), self.key, self.iv
            ))
            return True
        except Exception as e:
            print(f"[-] {self.uid} Auth error: {e}")
            return False

    def _connect_online(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.online_ip, self.online_port))
            sock.send(bytes.fromhex(self.auth_token))
            resp = sock.recv(4096)
            if not resp:
                sock.close()
                return None
            print(f"[+] {self.uid} Online connected")
            return sock
        except Exception as e:
            print(f"[-] {self.uid} Online connect failed: {e}")
            return None

    def _reader(self, sock):
        while self.running:
            try:
                data = sock.recv(4096)
                if not data:
                    break
            except Exception as e:
                print(f"[{self.uid}] Reader error: {e}")
                break
        self.running = False
        self._need_reconnect = True

    def _connect(self):
        print(f"[🔄] Connecting {self.uid}...")
        
        if not self._full_auth():
            print(f"[-] {self.uid} Auth failed — Marked for retry")
            self._need_reconnect = True
            return
        
        sock = self._connect_online()
        if not sock:
            print(f"[-] {self.uid} Online connection failed")
            self._need_reconnect = True
            return
        
        self.online_sock = sock
        self.running = True
        self._need_reconnect = False
        
        threading.Thread(target=self._reader, args=(sock,), daemon=True).start()
        
        with connected_clients_lock:
            connected_clients[self.uid] = self
            print(f"[✅] {self.uid} online. Total: {len(connected_clients)}")
        
        # IMMEDIATE SPAM DISPATCH — অনলাইনে আসার সাথে সাথে
        print(f"[🚀] {self.uid}: Auto-dispatching spam...")
        threading.Thread(target=dispatch_spam_for_client, args=(self,), daemon=True).start()

    def reconnect(self):
        print(f"[🔄] {self.uid}: Reconnecting...")
        if self.online_sock:
            try:
                self.online_sock.close()
            except:
                pass
        self.running = False
        time.sleep(3)  # Increased delay
        self._connect()

    def force_disconnect(self):
        self.running = False
        if self.online_sock:
            try:
                self.online_sock.close()
            except:
                pass
        self.online_sock = None
        with connected_clients_lock:
            if self.uid in connected_clients:
                del connected_clients[self.uid]

# ========== FIXED AUTO-RECONNECT WORKER ==========
def auto_reconnect_worker():
    """প্রতি ১৫ সেকেন্ডে ডিসকানেক্টেড অ্যাকাউন্ট রিকানেক্ট ট্রাই"""
    print("[🔄] Auto-reconnect worker started — 15s interval")
    
    while True:
        try:
            accounts = load_accounts()
            
            with connected_clients_lock:
                connected_uids = set(connected_clients.keys())
                disconnected = [uid for uid in connected_clients if connected_clients[uid]._need_reconnect]
            
            # Reconnect disconnected first
            for uid in disconnected:
                try:
                    client = connected_clients[uid]
                    print(f"[🔄] Reconnecting disconnected: {uid}")
                    threading.Thread(target=client.reconnect, daemon=True).start()
                    time.sleep(2)
                except Exception as e:
                    print(f"[❌] Reconnect error for {uid}: {e}")
            
            # Connect new accounts not in connected_clients
            for uid, pwd in accounts:
                if uid not in connected_uids:
                    print(f"[🔄] Connecting new/banned account: {uid}")
                    threading.Thread(target=lambda u=uid, p=pwd: FF_CLient(u, p), daemon=True).start()
                    time.sleep(2)
            
            time.sleep(15)
            
        except Exception as e:
            print(f"[ERROR] Auto-reconnect: {e}")
            time.sleep(5)

# ========== FIXED GENERATOR SYSTEM ==========
def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     🔥  ʙᴅ➺ꫝᴅᴍɪɴ  ULTRA ACCOUNT GENERATOR + SPAMMER  🔥      ║
║                                                              ║
║              Premium Cyber Infrastructure v4.0                 ║
║              UNLIMITED GEN + PERSISTENT SPAM                 ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""")

def print_main_menu():
    print("""
┌─────────────────────────────────────────────────────────────┐
│  📋 MAIN MENU                                               │
│                                                             │
│     1) 🚀 START GENERATOR (UNLIMITED)                       │
│     2) 📁 View Saved Accounts                               │
│     3) 📊 Statistics                                        │
│     4) ℹ️  About                                            │
│     5) 🛠️  ULTIMATE ADMIN PANEL                           │
│     6) 🚪 Exit                                              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
""")

def print_region_menu():
    print("""
┌─────────────────────────────────────────────────────────────┐
│  🌍 SELECT REGION                                           │
│                                                             │
│     1)  ME  (ar)    7)  PK  (ur)                            │
│     2)  IND (hi)    8)  TW  (zh)                            │
│     3)  ID  (id)    9)  CIS (ru)                            │
│     4)  VN  (vi)    10) SAC (es)                            │
│     5)  TH  (th)    11) 👻 GHOST Mode                       │
│     6)  BD  (bn)                                            │
│     00) ⬅️  BACK                                            │
│     000) 🚪 EXIT                                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
""")

def print_gen_config(name, json_name, region):
    print(f"""
┌─────────────────────────────────────────────────────────────┐
│  🚀 GENERATION CONFIG — UNLIMITED MODE                      │
│                                                             │
│     🎯 Target      : 999999999                              │
│     ⚡ Threads     : 64 (MAX)                               │
│     🔌 APIs       : 20 (ROTATING)                           │
│     📝 Auto Bio   : ON                                      │
│     🔥 Auto-Act   : ON                                      │
│     🌍 Region     : {region:<5}│
│     👑 Level      : OWNER                                   │
│     🔄 Retries    : UNLIMITED                               │
│     📦 Version    : OB53 — NEW API ENDPOINTS                │
│     👤 Acc Name   : {name:<5}│
│     📄 JSON File  : {json_name}-bd.json                     │
│     ✅ Activated  : {json_name}-bd-activated.json            │
│     📝 Name Prefix: {name:<5}│
│     🔑 Pass Prefix: KAWSAR                                  │
│     💎 Rarity     : 3                                       │
│     ♻️  Restart   : AUTO (gen.py crash hole auto restart)   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
""")

def print_stats():
    with gen_stats['lock']:
        s = gen_stats['success']
        f = gen_stats['failed']
        t = gen_stats['total']
    print(f"""
┌─────────────────────────────────────────────────────────────┐
│  📊 GENERATOR STATS                                         │
│                                                             │
│     ✅ Successful : {s:<6}                                   │
│     ❌ Failed     : {f:<6}                                   │
│     📈 Total      : {t:<6}                                   │
│     🤖 Connected  : {len(connected_clients):<<6}                                   │
│     📌 Queue Size : {len(spam_queue):<<6}                                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
""")

# ========== FIXED GEN.PY HANDLER — AUTO RESTART ==========
def start_gen_py(name_prefix, json_name, region_code):
    """
    gen.py start করবে — ক্র্যাশ হলে auto-restart
    """
    global gen_process
    
    def run_gen():
        try:
            if not os.path.exists('gen.py'):
                print("[❌] gen.py file not found!")
                return None

            env = os.environ.copy()
            env['PYTHONUNBUFFERED'] = '1'

            os.makedirs(GEN_FOLDER, exist_ok=True)
            os.makedirs(ACTIVATED_FOLDER, exist_ok=True)

            proc = subprocess.Popen(
                [sys.executable, 'gen.py'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                env=env,
                text=True,
                bufsize=1
            )

            time.sleep(1)
            inputs = ["1\n", f"{name_prefix}\n", f"{json_name}\n", f"{region_code}\n"]
            
            for inp in inputs:
                try:
                    proc.stdin.write(inp)
                    proc.stdin.flush()
                    time.sleep(0.5)
                except:
                    pass

            print(f"[✅] gen.py started (PID: {proc.pid})")
            return proc
            
        except Exception as e:
            print(f"[❌] Failed to start gen.py: {e}")
            return None

    def monitor_gen():
        """gen.py monitor — ক্র্যাশ হলে auto restart"""
        global gen_process
        restart_count = 0
        
        while gen_stats['running'] and restart_count < 100:  # Max 100 restarts
            if gen_process is None or gen_process.poll() is not None:
                print(f"[🔄] gen.py crashed or not running. Restarting... (Attempt {restart_count + 1})")
                gen_process = run_gen()
                restart_count += 1
                time.sleep(5)
            else:
                # Check if still producing
                time.sleep(10)
                
                # Check output to see if stuck
                try:
                    if gen_process.stdout:
                        line = gen_process.stdout.readline()
                        if line:
                            print(f"[gen.py] {line.strip()}")
                except:
                    pass
            
            time.sleep(5)
        
        print("[🛑] gen.py monitor stopped")

    gen_process = run_gen()
    
    # Start monitor thread
    threading.Thread(target=monitor_gen, daemon=True).start()
    
    return gen_process

def stop_gen_py():
    global gen_process
    if gen_process:
        try:
            gen_process.terminate()
            time.sleep(1)
            if gen_process.poll() is None:
                gen_process.kill()
            print("[🛑] gen.py stopped.")
        except:
            pass
        gen_process = None

def read_activated_json(json_name):
    """Read accounts from ACTIVATED folder — multiple file checks"""
    try:
        possible_names = [
            f"{json_name}-bd-activated.json",
            f"{json_name}-activated.json",
            f"bd-bd-activated.json",
            f"bd-activated.json",
            f"{json_name}.json",
            "activated.json"
        ]

        for fname in possible_names:
            json_path = os.path.join(ACTIVATED_FOLDER, fname)
            if os.path.exists(json_path):
                with open(json_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict) and 'accounts' in data:
                    return data['accounts']
                elif isinstance(data, dict):
                    # Maybe single account object
                    return [data]
        return []
    except Exception as e:
        print(f"[ERROR] read_activated_json: {e}")
        return []

def save_to_erentxt(uid, password):
    """Save uid:pass to Eren.txt + backup"""
    try:
        with open(EREN_FILE, "a", encoding="utf-8") as f:
            f.write(f"{uid}:{password}\n")
        
        # Backup every 50 accounts
        if len(processed_uids) % 50 == 0:
            import shutil
            shutil.copy(EREN_FILE, EREN_BACKUP)
            
        return True
    except Exception as e:
        print(f"[ERROR] Failed to save: {e}")
        return False

def connect_account(uid, password):
    """Connect single account with retry"""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            with connected_clients_lock:
                if uid in connected_clients:
                    client = connected_clients[uid]
                    if client.online_sock and not client._need_reconnect:
                        return True
                    client.reconnect()
                    return client.online_sock is not None

            client = FF_CLient(uid, password)
            return client.online_sock is not None
            
        except Exception as e:
            print(f"[ERROR] Connect {uid} attempt {attempt+1}: {e}")
            time.sleep(2)
    
    return False

def process_new_accounts(json_name, auto_connect=True):
    """Process new accounts — FIXED for unlimited generation"""
    accounts = read_activated_json(json_name)
    new_count = 0

    for account in accounts:
        try:
            uid = str(account.get('uid', account.get('UID', account.get('id', ''))))
            password = str(account.get('password', account.get('pass', account.get('pwd', ''))))

            if not uid or not password:
                continue

            if uid in processed_uids:
                continue

            if save_to_erentxt(uid, password):
                processed_uids.add(uid)
                new_count += 1

                with gen_stats['lock']:
                    gen_stats['success'] += 1
                    gen_stats['total'] += 1

                print(f"[✅] NEW: {uid} | Password: {password[:20]}...")

                if auto_connect:
                    print(f"[🔄] Connecting {uid}...")
                    threading.Thread(target=connect_account, args=(uid, password), daemon=True).start()
                    time.sleep(1)
            else:
                with gen_stats['lock']:
                    gen_stats['failed'] += 1
                    gen_stats['total'] += 1
                    
        except Exception as e:
            print(f"[ERROR] Processing: {e}")
            with gen_stats['lock']:
                gen_stats['failed'] += 1
                gen_stats['total'] += 1

    return new_count

def generator_monitor(json_name):
    """Monitor — FIXED for unlimited accounts"""
    print(f"\n[🚀] Monitoring activated accounts...")
    print(f"[📁] Saving to: {EREN_FILE}")
    print(f"[💾] Spam Queue: Persistent")
    print(f"[♻️] Auto-restart: ON (gen.py crash hole auto restart)")
    print("=" * 60)

    if not os.path.exists(EREN_FILE):
        open(EREN_FILE, 'w').close()
        print(f"[✓] Created {EREN_FILE}")

    try:
        with open(EREN_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and ':' in line:
                    uid = line.split(':', 1)[0]
                    processed_uids.add(uid)
        print(f"[✓] Loaded {len(processed_uids)} existing accounts")
    except:
        pass

    last_count = len(processed_uids)
    stuck_count = 0

    while gen_stats['running']:
        try:
            new_accounts = process_new_accounts(json_name, auto_connect=True)
            
            if new_accounts > 0:
                print(f"[📊] +{new_accounts} new | Total: {len(processed_uids)} | Bots: {len(connected_clients)}")
                stuck_count = 0
            else:
                stuck_count += 1
            
            # If stuck for too long, maybe gen.py stopped
            if stuck_count > 20:  # ~60 seconds
                print(f"[⚠️] No new accounts for {stuck_count} checks. Checking gen.py...")
                global gen_process
                if gen_process is None or gen_process.poll() is not None:
                    print("[🔄] gen.py seems dead. Restarting...")
                    start_gen_py(gen_stats['name_prefix'], json_name, "6")
                stuck_count = 0
            
            # Print stats every 10 checks
            if stuck_count % 10 == 0:
                print_stats()

            time.sleep(3)

        except Exception as e:
            print(f"[ERROR] Monitor: {e}")
            traceback.print_exc()
            time.sleep(5)

def start_generator(name_prefix, json_name, region_code):
    gen_stats['running'] = True
    gen_stats['name_prefix'] = name_prefix

    start_gen_py(name_prefix, json_name, region_code)

    thread = threading.Thread(target=generator_monitor, args=(json_name,), daemon=True)
    thread.start()
    return thread

def stop_generator():
    gen_stats['running'] = False
    stop_gen_py()
    with spam_queue_lock:
        spam_queue.clear()
    print("\n[🛑] Stopped.")

def cleanup():
    stop_gen_py()

atexit.register(cleanup)

# ========== Load accounts ==========
def load_accounts():
    accounts = []
    try:
        with open(EREN_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and ":" in line and not line.startswith("#"):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        accounts.append((parts[0], parts[1]))
    except FileNotFoundError:
        print(f"[⚠️] {EREN_FILE} not found")
    return accounts

def start_all_accounts():
    """Connect all accounts with batching"""
    accounts = load_accounts()
    print(f"[📂] Loading {len(accounts)} accounts from {EREN_FILE}...")
    
    # Connect in batches of 10
    batch_size = 10
    for i in range(0, len(accounts), batch_size):
        batch = accounts[i:i+batch_size]
        for uid, pwd in batch:
            print(f"[🔄] Connecting {uid}...")
            threading.Thread(target=lambda u=uid, p=pwd: FF_CLient(u, p), daemon=True).start()
            time.sleep(2)
        
        print(f"[✅] Batch {i//batch_size + 1} done. Sleeping...")
        time.sleep(10)
    
    print(f"[✅] All loaded. Connected: {len(connected_clients)}")

# ========== Flask Web App ==========
app = Flask(__name__)

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ʙᴅ➺ꫝᴅᴍɪɴ ULTRA TERMINAL</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@500;600;700&display=swap" rel="stylesheet">

    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Rajdhani', sans-serif; -webkit-font-smoothing: antialiased; }
        body {
            background: linear-gradient(135deg, #0a0a0a 0%, #1a0000 25%, #001a00 50%, #0a0a1a 75%, #1a0a00 100%);
            background-size: 400% 400%;
            animation: gradientShift 15s ease infinite;
            color: #ffffff; min-height: 100vh;
        }
        @keyframes gradientShift { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }
        body::before {
            content: ''; position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: radial-gradient(circle at 20% 50%, rgba(255,0,0,0.08) 0%, transparent 50%), radial-gradient(circle at 80% 50%, rgba(0,255,0,0.08) 0%, transparent 50%), radial-gradient(circle at 50% 80%, rgba(255,215,0,0.05) 0%, transparent 50%);
            pointer-events: none; z-index: -1;
        }
        .brand-name {
            background: linear-gradient(90deg, #ff0000, #ff6b00, #ffd700, #00ff00, #00d2ff, #ff00ff, #ff0000);
            background-size: 200% auto; -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
            animation: rainbowFlow 3s linear infinite; font-weight: 900; letter-spacing: 2px; filter: drop-shadow(0 0 10px rgba(255,0,0,0.5));
        }
        @keyframes rainbowFlow { 0% { background-position: 0% center; } 100% { background-position: 200% center; } }
        .brand-name-small { background: linear-gradient(90deg, #ff3333, #ffaa00, #ffdd44); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; font-weight: 700; }
        .stat-box {
            background: linear-gradient(145deg, rgba(20,0,0,0.8), rgba(0,20,0,0.8));
            border: 1px solid rgba(255,0,0,0.3); border-radius: 16px; text-align: center; padding: 15px 10px;
            box-shadow: 0 0 20px rgba(255,0,0,0.1), inset 0 0 15px rgba(0,255,0,0.05); transition: all 0.3s ease;
        }
        .stat-box:hover { border-color: rgba(255,215,0,0.5); box-shadow: 0 0 30px rgba(255,215,0,0.2); transform: translateY(-2px); }
        .stat-val { font-size: 2.2rem; font-weight: 700; background: linear-gradient(180deg, #ff3333, #ffaa00); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; line-height: 1; filter: drop-shadow(0 0 8px rgba(255,50,50,0.6)); }
        .stat-lbl { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; color: #ff8888; margin-top: 4px; font-weight: 600; }
        .nav-tab {
            background: linear-gradient(145deg, #1a0000, #001a00); border: 1px solid rgba(255,0,0,0.3); color: #ff6b6b;
            border-radius: 30px; font-weight: 700; font-size: 0.85rem; letter-spacing: 1px;
            transition: all 0.25s cubic-bezier(0.4,0,0.2,1); will-change: background, box-shadow;
        }
        .nav-tab.active { background: linear-gradient(90deg, #ff0000, #ff6b00); color: #ffffff; box-shadow: 0 0 25px rgba(255,0,0,0.5), 0 0 50px rgba(255,100,0,0.3); border-color: #ff6b00; }
        .cyber-link-btn {
            background: linear-gradient(145deg, rgba(255,0,0,0.1), rgba(0,255,0,0.05)); border: 1px solid rgba(255,0,0,0.3);
            color: #ff6b6b; font-size: 0.8rem; font-weight: 700; letter-spacing: 1px; padding: 6px 16px; border-radius: 20px;
            transition: all 0.25s ease; display: inline-flex; align-items: center; gap: 6px;
        }
        .cyber-link-btn:hover { background: linear-gradient(90deg, #ff0000, #ff6b00); color: #ffffff; box-shadow: 0 0 20px rgba(255,0,0,0.5); border-color: #ff6b00; transform: scale(1.05); }
        .cyber-panel {
            background: linear-gradient(145deg, rgba(20,0,0,0.6), rgba(0,10,0,0.6), rgba(10,0,20,0.6));
            border: 1px solid rgba(255,0,0,0.2); border-radius: 20px; padding: 22px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5), 0 0 30px rgba(255,0,0,0.05); position: relative; overflow: hidden;
        }
        .cyber-panel::before {
            content: ''; position: absolute; top: -2px; left: -2px; right: -2px; bottom: -2px;
            background: linear-gradient(45deg, #ff0000, #00ff00, #ffd700, #ff0000); border-radius: 22px;
            z-index: -1; opacity: 0.3; filter: blur(10px);
        }
        .panel-title-bar { display: flex; align-items: center; gap: 10px; font-size: 1.1rem; font-weight: 700; letter-spacing: 1px; color: #ff6b6b; text-shadow: 0 0 10px rgba(255,0,0,0.3); margin-bottom: 20px; }
        .panel-indicator { width: 4px; height: 18px; background: linear-gradient(180deg, #ff0000, #ff6b00); border-radius: 2px; box-shadow: 0 0 8px #ff0000; }
        .cyber-input {
            background: linear-gradient(145deg, #0a0000, #000a00); border: 1px solid rgba(255,0,0,0.3); border-radius: 30px;
            color: #ffffff; font-size: 1rem; padding: 14px 24px; width: 100%; outline: none; transition: all 0.25s ease;
        }
        .cyber-input:focus { border-color: #ff6b00; box-shadow: inset 0 0 8px rgba(255,100,0,0.2), 0 0 15px rgba(255,0,0,0.2); }
        .cyber-input::placeholder { color: #664444; }
        .btn-glow-cyan {
            background: linear-gradient(90deg, #ff0000, #ff6b00); color: #ffffff; font-weight: 700; border-radius: 30px;
            font-size: 1rem; letter-spacing: 1px; box-shadow: 0 0 20px rgba(255,0,0,0.4);
            transition: all 0.2s cubic-bezier(0.4,0,0.2,1); will-change: transform, box-shadow; border: none;
        }
        .btn-glow-cyan:hover { transform: scale(1.02); box-shadow: 0 0 35px rgba(255,0,0,0.7), 0 0 60px rgba(255,100,0,0.4); background: linear-gradient(90deg, #ff3333, #ff8800); }
        .btn-glow-pink {
            background: linear-gradient(90deg, #ff0055, #ff00aa); color: #ffffff; font-weight: 700; border-radius: 30px;
            font-size: 1rem; letter-spacing: 1px; box-shadow: 0 0 20px rgba(255,0,85,0.4);
            transition: all 0.2s cubic-bezier(0.4,0,0.2,1); will-change: transform, box-shadow; border: none;
        }
        .btn-glow-pink:hover { transform: scale(1.02); box-shadow: 0 0 35px rgba(255,0,85,0.7), 0 0 60px rgba(255,0,150,0.4); background: linear-gradient(90deg, #ff3388, #ff33cc); }
        .inline-stop-btn {
            background: linear-gradient(145deg, rgba(255,0,85,0.2), rgba(255,0,150,0.1)); border: 1px solid #ff0055;
            color: #ff5588; font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 20px; cursor: pointer; transition: all 0.2s ease;
        }
        .inline-stop-btn:hover { background: linear-gradient(90deg, #ff0055, #ff00aa); color: #ffffff; box-shadow: 0 0 15px #ff0055; transform: scale(1.1); }
        .panel-scroll::-webkit-scrollbar { width: 4px; }
        .panel-scroll::-webkit-scrollbar-track { background: transparent; }
        .panel-scroll::-webkit-scrollbar-thumb { background: linear-gradient(180deg, #ff0000, #00ff00); border-radius: 10px; }
        .toast-box { opacity: 0; transform: translateY(5px); transition: all 0.3s cubic-bezier(0.4,0,0.2,1); pointer-events: none; }
        .toast-box.show { opacity: 1; transform: translateY(0); }
        .header-title { background: linear-gradient(90deg, #ff0000, #ffd700, #00ff00, #00d2ff, #ff00ff, #ff0000); background-size: 200% auto; -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; animation: rainbowFlow 4s linear infinite; font-weight: 900; }
        .footer-brand { background: linear-gradient(90deg, #ff3333, #ffaa00, #ffdd44); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; font-weight: 900; animation: rainbowFlow 3s linear infinite; background-size: 200% auto; }
        .subtitle-text { color: #ff8888; }
        @keyframes multiColorPulse { 0%,100% { box-shadow: 0 0 5px rgba(255,0,0,0.5); } 25% { box-shadow: 0 0 15px rgba(0,255,0,0.5); } 50% { box-shadow: 0 0 10px rgba(255,215,0,0.5); } 75% { box-shadow: 0 0 15px rgba(255,0,255,0.5); } }
        .multi-pulse { animation: multiColorPulse 2s infinite; }
        .queue-badge { background: linear-gradient(90deg, #ff0055, #ff00aa); font-size: 0.65rem; padding: 2px 8px; border-radius: 10px; font-weight: 700; }
        .status-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
        .status-online { background: #00ff00; box-shadow: 0 0 8px #00ff00; }
        .status-offline { background: #ff0000; box-shadow: 0 0 8px #ff0000; }
    </style>
</head>
<body class="py-6 px-4 max-w-xl mx-auto flex flex-col justify-start">

    <header class="flex flex-col items-center justify-center my-4 text-center">
        <h1 class="text-3xl font-extrabold tracking-wider uppercase text-shadow">
            <span class="brand-name">ʙᴅ➺ꫝᴅᴍɪɴ</span> CONTROL PANEL
        </h1>
        <p class="text-xs font-semibold tracking-widest subtitle-text uppercase mt-1 mb-3">UNLIMITED GEN + PERSISTENT SPAM v4.1</p>
        <div class="flex items-center gap-3 mt-1 mb-2">
            <a href="https://t.me/BD_ADMIN_CODER_OFFICIAL" target="_blank" class="cyber-link-btn"><i class="fa-brands fa-telegram text-base"></i> TELEGRAM CHANNEL</a>
            <a href="https://t.me/BD_ADMIN_20" target="_blank" class="cyber-link-btn" style="color:#00ff88;border-color:rgba(0,255,136,0.3);background:linear-gradient(145deg,rgba(0,255,136,0.1),rgba(0,200,100,0.05));"><i class="fa-solid fa-address-card text-base"></i> CONTACT DEVELOPER</a>
        </div>
    </header>

    <div class="grid grid-cols-3 gap-3 mb-4">
        <div class="stat-box"><div class="stat-val" id="activeSpamCount">0</div><div class="stat-lbl">Active Spam</div></div>
        <div class="stat-box"><div class="stat-val" id="queueCount">0</div><div class="stat-lbl">Queue Size</div></div>
        <div class="stat-box"><div class="stat-val" id="accCount">0</div><div class="stat-lbl">Connected</div></div>
    </div>

    <div class="grid grid-cols-3 gap-3 mb-6">
        <div class="stat-box" style="border-color:rgba(0,255,0,0.3);"><div class="stat-val" style="background:linear-gradient(180deg,#00ff00,#00aa00);-webkit-background-clip:text;" id="genSuccess">0</div><div class="stat-lbl" style="color:#88ff88;">Gen Success</div></div>
        <div class="stat-box" style="border-color:rgba(255,0,0,0.3);"><div class="stat-val" style="background:linear-gradient(180deg,#ff3333,#ff0000);-webkit-background-clip:text;" id="genFailed">0</div><div class="stat-lbl" style="color:#ff8888;">Gen Failed</div></div>
        <div class="stat-box" style="border-color:rgba(255,215,0,0.3);"><div class="stat-val" style="background:linear-gradient(180deg,#ffd700,#ffaa00);-webkit-background-clip:text;" id="genTotal">0</div><div class="stat-lbl" style="color:#ffdd88;">Gen Total</div></div>
    </div>

    <div class="w-full mb-6">
        <button class="nav-tab active w-full py-2.5 px-2 flex items-center justify-center gap-1.5">
            <i class="fa-solid fa-gamepad text-xs"></i> SPAM 
            <span class="queue-badge" id="navQueueBadge">UNLIMITED MODE</span>
        </button>
    </div>

    <div class="space-y-6">
        <div class="cyber-panel">
            <div class="panel-title-bar"><div class="panel-indicator"></div><i class="fa-solid fa-crosshairs text-[#ff3366]"></i><h2><span class="brand-name-small">ʙᴅ➺ꫝᴅᴍɪɴ</span> UNLIMITED MODE</h2></div>
            <div class="space-y-4">
                <input type="text" id="targetUid" class="cyber-input" placeholder="Enter Target UID">
                <input type="number" id="duration" class="cyber-input" placeholder="Duration (Minutes) — 0 = Forever">
                <button id="startBtn" class="btn-glow-cyan w-full py-3.5 flex items-center justify-center gap-2">
                    <i class="fa-solid fa-play text-xs"></i> QUEUE TARGET
                </button>
            </div>
            <div id="startMessage" class="toast-box bg-red-500/10 border border-red-500/30 text-red-400 rounded-xl p-3 mt-3 text-sm font-medium flex items-center gap-2"></div>
        </div>

        <div class="cyber-panel">
            <div class="panel-title-bar"><div class="panel-indicator" style="background:linear-gradient(180deg,#ff0055,#ff00aa);box-shadow:0 0 8px #ff0055;"></div><i class="fa-solid fa-octagon-xmark text-red-500"></i><h2>TERMINATION SYSTEM</h2></div>
            <div class="space-y-4">
                <input type="text" id="stopTargetUid" class="cyber-input" placeholder="Enter UID to Stop">
                <button id="stopBtn" class="btn-glow-pink w-full py-3.5 flex items-center justify-center gap-2">
                    <i class="fa-solid fa-square text-xs"></i> STOP OPERATION
                </button>
            </div>
            <div id="stopMessage" class="toast-box bg-red-500/10 border border-red-500/30 text-red-400 rounded-xl p-3 mt-3 text-sm font-medium flex items-center gap-2"></div>
        </div>

        <div class="cyber-panel">
            <div class="panel-title-bar"><div class="panel-indicator" style="background:linear-gradient(180deg,#ff0000,#ffd700);box-shadow:0 0 8px #ff0000;"></div><i class="fa-solid fa-satellite-dish"></i><h2><span class="brand-name-small">ʙᴅ➺ꫝᴅᴍɪɴ</span> ACTIVE PIPELINE</h2></div>
            <div id="activeTargets" class="text-center text-sm text-gray-500 py-2 flex flex-col items-center gap-3">
                <span class="flex items-center gap-2"><i class="fa-solid fa-mailbox"></i> No active vectors</span>
            </div>
        </div>

        <div class="cyber-panel">
            <div class="panel-title-bar"><div class="panel-indicator"></div><i class="fa-solid fa-robot"></i><h2>CONNECTED <span class="brand-name-small">ʙᴅ➺ꫝᴅᴍɪɴ</span> BOTS</h2></div>
            <div class="panel-scroll overflow-y-auto max-h-[110px] space-y-2" id="accountList">
                <div class="text-center text-sm text-gray-500 py-2 flex items-center justify-center gap-2">
                    <i class="fa-solid fa-circle-notch animate-spin text-xs"></i> Scanning cluster cores...
                </div>
            </div>
        </div>
    </div>

    <footer class="mt-8 text-center text-[11px] font-semibold text-[#ff8888] tracking-widest uppercase">
        System Managed & Engineered By <span class="footer-brand">ʙᴅ➺ꫝᴅᴍɪɴ</span> &copy; 2026
    </footer>

    <script>
        function triggerStopFromTarget(uid) { 
            document.getElementById('stopTargetUid').value = uid; 
            document.getElementById('stopBtn').click(); 
        }
        
        function fetchStatus() {
            fetch('/api/status').then(res => res.json()).then(data => {
                document.getElementById('accCount').innerText = data.connected_accounts;
                document.getElementById('activeSpamCount').innerText = data.active_spam.length;
                document.getElementById('queueCount').innerText = data.queue_size;
                document.getElementById('genSuccess').innerText = data.gen_success;
                document.getElementById('genFailed').innerText = data.gen_failed;
                document.getElementById('genTotal').innerText = data.gen_total;
                
                const accListDiv = document.getElementById('accountList');
                if (data.accounts && data.accounts.length) {
                    accListDiv.innerHTML = data.accounts.map(acc => {
                        const status = acc.online ? 'status-online' : 'status-offline';
                        return `<div class="text-xs account-node px-4 py-2.5 rounded-full text-gray-300 flex items-center justify-between">
                            <span class="flex items-center gap-2">
                                <span class="status-dot ${status}"></span> 
                                <span class="brand-name-small">ʙᴅ➺ꫝᴅᴍɪɴ</span>_NODE
                            </span>
                            <span class="text-gray-400 font-mono">${acc.uid}</span>
                        </div>`;
                    }).join('');
                } else { 
                    accListDiv.innerHTML = '<div class="text-gray-500 text-sm text-center py-2"><i class="fa-solid fa-robot opacity-40 mr-1.5"></i> No active bot servers linked</div>'; 
                }
                
                const targetsDiv = document.getElementById('activeTargets');
                if (data.active_spam.length) {
                    targetsDiv.innerHTML = data.active_spam.map(t => 
                        `<div class="w-full bg-[#091926] border border-[#ff0055]/20 px-4 py-2 rounded-full flex items-center justify-between shadow-inner multi-pulse">
                            <span class="flex items-center gap-2 text-xs text-gray-300 font-mono">
                                <span class="w-1.5 h-1.5 rounded-full bg-[#ff0055] animate-pulse"></span> 
                                PIPELINE UID: ${t.uid} | STATUS: ${t.status.toUpperCase()}${t.duration ? ' | ⏱️ '+t.duration+'m' : ' | ♾️ FOREVER'}
                            </span>
                            <button onclick="triggerStopFromTarget('${t.uid}')" class="inline-stop-btn">
                                <i class="fa-solid fa-stop text-[8px] mr-1"></i> STOP
                            </button>
                        </div>`
                    ).join('');
                } else { 
                    targetsDiv.innerHTML = '<span class="text-gray-500 text-sm flex items-center gap-2 py-2"><i class="fa-solid fa-envelope-open opacity-40"></i> No active vectors running</span>'; 
                }
            }).catch(err => console.error(err));
        }
        
        function showMessage(elementId, text, isError = false) {
            const el = document.getElementById(elementId);
            el.innerHTML = isError ? `<i class="fa-solid fa-triangle-exclamation"></i> <span>${text}</span>` : `<i class="fa-solid fa-circle-check"></i> <span>${text}</span>`;
            if (isError) { 
                el.classList.remove('bg-emerald-500/10','border-emerald-500/30','text-emerald-400'); 
                el.classList.add('bg-red-500/10','border-red-500/30','text-red-400'); 
            } else { 
                el.classList.remove('bg-red-500/10','border-red-500/30','text-red-400'); 
                el.classList.add('bg-emerald-500/10','border-emerald-500/30','text-emerald-400'); 
            }
            el.classList.add('show'); 
            setTimeout(() => { el.classList.remove('show'); }, 3500);
        }
        
        document.getElementById('startBtn').onclick = () => {
            const uid = document.getElementById('targetUid').value.trim();
            const duration = document.getElementById('duration').value.trim();
            if (!uid) { showMessage('startMessage', 'Bhai, please target UID input karo!', true); return; }
            const url = `/start_spam?uid=${encodeURIComponent(uid)}` + (duration ? `&duration=${parseInt(duration)}` : '');
            fetch(url).then(res => res.json()).then(data => {
                if (data.error) { showMessage('startMessage', data.error, true); } 
                else { showMessage('startMessage', `<span class="brand-name-small">ʙᴅ➺ꫝᴅᴍɪɴ</span> Queued: ${data.status} | Bots: ${data.bots_online}`); 
                    document.getElementById('targetUid').value = ''; 
                    document.getElementById('duration').value = ''; 
                    fetchStatus(); 
                }
            }).catch(err => showMessage('startMessage', 'Server Transmission Failed', true));
        };
        
        document.getElementById('stopBtn').onclick = () => {
            const uid = document.getElementById('stopTargetUid').value.trim();
            if (!uid) { showMessage('stopMessage', 'Bhai, stop korar jonno UID oboshshoi dorkar!', true); return; }
            fetch(`/stop_spam?uid=${encodeURIComponent(uid)}`).then(res => res.json()).then(data => {
                if (data.error) { showMessage('stopMessage', data.error, true); } 
                else { showMessage('stopMessage', `<span class="brand-name-small">ʙᴅ➺ꫝᴅᴍɪɴ</span> Aborted: ${data.status}`); 
                    document.getElementById('stopTargetUid').value = ''; 
                    fetchStatus(); 
                }
            }).catch(err => showMessage('stopMessage', 'Server Transmission Failed', true));
        };
        
        fetchStatus(); 
        setInterval(fetchStatus, 3000);
    </script>
</body>
</html>"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/status')
def api_status():
    with spam_queue_lock:
        active = [{'uid': uid, 'status': info['status'], 'duration': info.get('duration')} 
                  for uid, info in spam_queue.items()]
        queue_size = len(spam_queue)
    with connected_clients_lock:
        acc_list = [{'uid': uid, 'online': client.online_sock is not None and not client._need_reconnect} 
                    for uid, client in connected_clients.items()]
    with gen_stats['lock']:
        gen_success = gen_stats['success']
        gen_failed = gen_stats['failed']
        gen_total = gen_stats['total']
    return jsonify({
        'connected_accounts': len(connected_clients),
        'accounts': acc_list,
        'active_spam': active,
        'queue_size': queue_size,
        'gen_success': gen_success,
        'gen_failed': gen_failed,
        'gen_total': gen_total
    })

@app.route('/start_spam')
def start_spam_route():
    target = request.args.get('uid')
    duration = request.args.get('duration', type=int)
    if not target:
        return jsonify({'error': 'uid parameter chahiye'}), 400
    
    with spam_queue_lock:
        if target in spam_queue and spam_queue[target]['status'] == 'active':
            return jsonify({'error': f'{target} pe already queued hai'}), 409
        
        spam_queue[target] = {
            'start_time': datetime.now(),
            'duration': duration,
            'status': 'active',
            'last_spam': None
        }
    
    # IMMEDIATE DISPATCH — বট থাকলে সাথে সাথে স্প্যাম
    with connected_clients_lock:
        bots_online = len(connected_clients)
        clients = list(connected_clients.values()) if connected_clients else []
    
    if clients:
        for client in clients:
            threading.Thread(target=send_spam_packets, args=(client, target, 10), daemon=True).start()
        status_msg = f"Spam queued + dispatched to {bots_online} bots"
    else:
        status_msg = "Spam QUEUED — Will auto-execute when accounts connect!"
    
    return jsonify({
        'status': status_msg,
        'target': target,
        'duration_minutes': duration,
        'bots_online': bots_online
    })

@app.route('/stop_spam')
def stop_spam_route():
    target = request.args.get('uid')
    if not target:
        return jsonify({'error': 'uid parameter chahiye'}), 400
    with spam_queue_lock:
        if target in spam_queue:
            spam_queue[target]['status'] = 'stopped'
            return jsonify({'status': f'{target} ka spam band kar diya'})
        else:
            return jsonify({'error': f'{target} pe koi spam nahi chal raha'}), 404

# ========== MAIN ENTRY POINT ==========
if __name__ == '__main__':
    print_banner()

    # Start workers
    threading.Thread(target=global_spam_worker, daemon=True).start()
    print("[✅] Global Spam Dispatcher started — 30s interval")

    threading.Thread(target=auto_reconnect_worker, daemon=True).start()
    print("[✅] Auto-reconnect worker started — 15s interval")

    print_main_menu()

    try:
        choice = input("[?] Choose: ").strip()
    except:
        choice = "1"

    if choice == "6":
        print("\n[👋] Exiting...")
        sys.exit(0)

    if choice == "1":
        print("\n┌─────────────────────────────────────────────────────────────┐")
        print("│  👤 CUSTOM ACCOUNT NAME                                     │")
        print("│  Enter the name to use for generated accounts:              │")
        print("└─────────────────────────────────────────────────────────────┘")
        try:
            name_prefix = input("> ").strip()
            if not name_prefix:
                name_prefix = "bd"
        except:
            name_prefix = "bd"

        print(f"\n✏️  Account Name: {name_prefix}")

        print("\n┌─────────────────────────────────────────────────────────────┐")
        print("│  📄 JSON FILE NAME                                          │")
        print("│  Enter JSON save file name (without .json):                 │")
        print("└─────────────────────────────────────────────────────────────┘")
        try:
            json_name = input("> ").strip()
            if not json_name:
                json_name = "bd"
        except:
            json_name = "bd"

        print(f"\n📄 JSON Name: {json_name}")

        print_region_menu()
        try:
            region_code = input("[?] Choose: ").strip()
        except:
            region_code = "6"

        region_map = {
            "1": "ME", "2": "IND", "3": "ID", "4": "VN", "5": "TH",
            "6": "BD", "7": "PK", "8": "TW", "9": "CIS", "10": "SAC",
            "11": "GHOST"
        }
        region = region_map.get(region_code, "BD")

        print(f"\n🌍 Region: {region}")

        print_gen_config(name_prefix, json_name, region)

        print(f"\n[✓] Name prefix: {name_prefix}")
        print(f"[✓] JSON: {json_name}-bd-activated.json")
        print(f"[✓] Region: {region}")
        print("[🔄] Starting gen.py + monitor + web server...")
        print(f"[📂] Watching: {ACTIVATED_FOLDER}")
        print(f"[📁] Output: {EREN_FILE}")
        print(f"[💾] SPAM QUEUE: Persistent")
        print(f"[♻️] AUTO-RESTART: ON (gen.py crash hole auto restart)")
        print(f"[🤖] AUTO-RECONNECT: 15s interval for banned accounts")

        gen_thread = start_generator(name_prefix, json_name, region_code)

        print("\n" + "=" * 60)
        print("[🚀] Generator started! UNLIMITED mode ON!")
        print("[🌐] Web panel ready!")
        print("[💾] Queue persists even with 0 bots!")
        print("[♻️] gen.py auto-restart if crashed!")
        print("=" * 60)

        print("\n[🤖] Connecting all accounts from Eren.txt...")
        threading.Thread(target=start_all_accounts, daemon=True).start()

        print_stats()

        port = int(os.environ.get("PORT", 5000))

        print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     🌐 WEB PANEL READY!                                      ║
║                                                              ║
║     📱 Local:   http://127.0.0.1:""" + str(port) + """                  ║
║     🌐 Network: http://0.0.0.0:""" + str(port) + """                   ║
║                                                              ║
║     📝 Eren.txt mein accounts save ho rahe hain             ║
║     🔄 Generator: UNLIMITED (auto-restart on crash)         ║
║     💾 SPAM QUEUE: Persistent mode ON                        ║
║     🔄 Auto-reconnect: 15s interval                          ║
║     📊 Check web panel for live stats                       ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""")

        app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
    else:
        print("\n[⚠️] Please select option 1 to start generator.")
        sys.exit(0)
