#!/usr/bin/env python3
"""RockSalt_v4_Fixed.py (GUI + CLI)

Defensive TLS capability probe & Multi-Tool.

Features:
- Threaded Proxy Switching (Round-Robin SOCKS/HTTP)
- Red/Dark "Cypher" Theme GUI
- Relay Agent support
- Deep TLS/SSL inspection
- I2P Settings Tab (Hidden Services & SAM Bridge)
- SOCKS5 9001 Tunnel Configuration
- Project RockSalt.py (Nmap & Shell Launcher)
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import itertools
import json
import logging
import queue
import re
import socket
import ssl
import sys
import threading
import time
import subprocess
import os
import platform
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Callable

# --- DEPENDENCY CHECK: PySocks ---
try:
    import socks
except ImportError:
    socks = None

# --- DEPENDENCY CHECK: i2plib ---
try:
    import asyncio
    import i2plib
    from i2plib.destination import Destination
    I2P_AVAILABLE = True
except ImportError:
    I2P_AVAILABLE = False

# --- DEPENDENCY CHECK: python-nmap ---
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# GUI imports
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext, ttk
except Exception:
    tk = None
    filedialog = None
    messagebox = None
    scrolledtext = None
    ttk = None


RANGE_RE = re.compile(r"^(\d+\.\d+\.\d+)\.(\d+)-(\d+)$")
_PROXY_LINE_RE = re.compile(
    r"^(?:(socks5|socks)://|(?:(http|connect)://))?\s*([^:\s]+)\s*:\s*(\d{1,5})\s*$",
    re.IGNORECASE,
)


# =============================================================================
#   GLOBAL VISUAL CONFIGURATION (RED CYPHER THEME)
# =============================================================================

# --- Main Window & Containers ---
UI_BG_MAIN = "#1e1e1e"          # Darker background
UI_FG_MAIN = "#ffffff"          # Main text color
UI_BG_PANE = "#121212"          # Very dark background for logs

# --- Red Theme Buttons ---
UI_BTN_BG = "#800000"           # Deep Red / Maroon
UI_BTN_FG = "#ffffff"           # White text
UI_BTN_ACTIVE_BG = "#ff3333"    # Bright Red (Hover/Click)
UI_BTN_ACTIVE_FG = "#ffffff"    # White text on active
UI_BTN_RELIEF = "raised"        # Border style
UI_BTN_BORDER = 1               # Border width

# --- Destructive Buttons (Cancel) ---
UI_BTN_CANCEL_BG = "#4a0000"    # Very Dark Red
UI_BTN_CANCEL_FG = "#aaaaaa"    # Dim text when disabled
UI_BTN_CANCEL_ACTIVE_BG = "#ff0000" # Pure Red
UI_BTN_CANCEL_ACTIVE_FG = "#ffffff" # White text on active (FIXED)

# --- Text Inputs (Entries & Spinboxes) ---
UI_ENTRY_BG = "#333333"         # Input background
UI_ENTRY_FG = "#ffffff"         # Input text color
UI_CURSOR_COLOR = "#ff3333"     # Red Blinking cursor
UI_SELECT_BG = "#b30000"        # Red selection highlight
UI_SELECT_FG = "#ffffff"        # Selection text color

# --- Checkboxes ---
UI_CHK_BG = UI_BG_MAIN          
UI_CHK_FG = UI_FG_MAIN          
UI_CHK_SELECT_COLOR = "#333333" 
UI_CHK_ACTIVE_BG = UI_BG_MAIN   
UI_CHK_ACTIVE_FG = "#ff3333"   

# --- Spinbox Specifics ---
UI_SPIN_ARROW_BG = UI_BTN_BG    

# --- Listbox Specifics ---
UI_LIST_BG = UI_BG_PANE
UI_LIST_FG = "#ffcccc"          # Light red text
UI_LIST_SELECT_BG = UI_SELECT_BG
UI_LIST_SELECT_FG = UI_SELECT_FG

# --- Progress Bar ---
UI_PROGRESS_BG = "#ff0000"      # Red Progress Bar
UI_PROGRESS_TROUGH = "#333333"

# --- TTK Styles (Tabs & Comboboxes) ---
UI_TTK_THEME = "clam"           
UI_TAB_BG = "#2b2b2b"
UI_TAB_FG = "#aaaaaa"
UI_TAB_SELECTED_BG = "#800000"  # Red Tab
UI_TAB_SELECTED_FG = "#ffffff"


# =============================================================================
#   CONSTANTS & DEFAULTS
# =============================================================================

GUI_GEOMETRY = "950x850" 
DEFAULT_RELAY_ADDR = "127.0.0.1:9009"
DEFAULT_RELAY_LISTEN = "0.0.0.0:9009"
DEFAULT_HEALTH_TIMEOUT = "2.5"
DEFAULT_TIMEOUT = 3.0
DEFAULT_WORKERS = 64
DEFAULT_OUTFILE = "wsman_tls_scan.jsonl"
DEFAULT_MAX_ATTEMPTS = 5

# I2P Defaults
DEFAULT_SAM_HOST = "127.0.0.1"
DEFAULT_SAM_PORT = 7656

DEFAULT_PORTS = [
    135, 139, 445, 5985, 5986, 47001, 8530, 8531, 8443, 9443
]

THREEDES_CIPHERS = (
    "DES-CBC3-SHA:"
    "EDH-RSA-DES-CBC3-SHA:"
    "ECDHE-RSA-DES-CBC3-SHA:"
    "ECDHE-ECDSA-DES-CBC3-SHA"
)

# -------------------------
# Logging
# -------------------------

logger = logging.getLogger("wsman_tls_scanner")
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
logger.addHandler(_handler)


class TkQueueHandler(logging.Handler):
    """Send formatted log messages to a queue for Tkinter UI consumption."""
    def __init__(self, q: queue.Queue):
        super().__init__()
        self.q = q

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            self.q.put((record.levelno, msg))
        except Exception:
            pass


# -------------------------
# Target expansion
# -------------------------

def expand_targets(targets: List[str]) -> List[str]:
    expanded: List[str] = []
    for t in targets:
        t = (t or "").strip()
        if not t:
            continue
        m = RANGE_RE.match(t)
        if m:
            base, start, end = m.group(1), int(m.group(2)), int(m.group(3))
            if start > end: start, end = end, start
            for last in range(start, end + 1): expanded.append(f"{base}.{last}")
            continue
        try:
            net = ipaddress.ip_network(t, strict=False)
            for ip in net.hosts(): expanded.append(str(ip))
            continue
        except ValueError:
            pass
        expanded.append(t)
    return expanded

# -------------------------
# Proxy Data Structures
# -------------------------

@dataclass
class ProxyEndpoint:
    scheme: str
    host: str
    port: int
    latency_ms: Optional[float] = None
    alive: bool = False
    pinned: bool = False

    def key(self) -> str:
        return f"{self.scheme.lower()}://{self.host}:{self.port}"

class ProxyRotationManager:
    def __init__(self, endpoints: List[ProxyEndpoint]):
        if not endpoints: raise ValueError("ProxyRotationManager initialized with empty list")
        if socks is None: raise ImportError("PySocks module not found. Run: pip install PySocks")
        self._cycle = itertools.cycle(endpoints)
        self._lock = threading.Lock()

    def get_socket(self, target_host: str, target_port: int, timeout: float) -> Tuple[socket.socket, str]:
        with self._lock: proxy = next(self._cycle)
        proxy_type = socks.PROXY_TYPE_SOCKS5 if proxy.scheme == "SOCKS5" else socks.PROXY_TYPE_HTTP
        s = socks.socksocket()
        s.set_proxy(proxy_type, proxy.host, proxy.port)
        s.settimeout(timeout)
        s.connect((target_host, target_port))
        return s, proxy.key()

# -------------------------
# TLS probing primitives
# -------------------------

def tcp_connect(host: str, port: int, timeout: float, proxy_mgr: Optional[ProxyRotationManager] = None) -> Optional[socket.socket]:
    try:
        if proxy_mgr:
            sock, _ = proxy_mgr.get_socket(host, port, timeout)
            return sock
        return socket.create_connection((host, port), timeout=timeout)
    except Exception:
        return None

def tls_handshake_basic(host: str, sock: socket.socket) -> Tuple[bool, Optional[str], Optional[str]]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return True, ssock.version(), ssock.cipher()[0]
    except Exception:
        return False, None, None

def tls_supports_legacy(host: str, port: int, timeout: float, proxy_mgr: Optional[ProxyRotationManager] = None) -> Optional[bool]:
    if getattr(ssl, "TLSVersion", None) is None: return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        sock = tcp_connect(host, port, timeout, proxy_mgr)
        if not sock: return False
        with sock:
            with ctx.wrap_socket(sock, server_hostname=host): return True
    except Exception:
        return False

def tls_probe_3des(host: str, port: int, timeout: float, proxy_mgr: Optional[ProxyRotationManager] = None) -> Tuple[Optional[bool], Optional[str]]:
    versions = [("TLSv1.0", getattr(ssl, "PROTOCOL_TLSv1", None)), ("TLSv1.1", getattr(ssl, "PROTOCOL_TLSv1_1", None)), ("TLSv1.2", getattr(ssl, "PROTOCOL_TLSv1_2", None))]
    for name, proto in versions:
        if proto is None: continue
        ctx = ssl.SSLContext(proto)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try: ctx.set_ciphers(THREEDES_CIPHERS)
        except ssl.SSLError: return None, None
        try:
            sock = tcp_connect(host, port, timeout, proxy_mgr)
            if sock:
                with sock, ctx.wrap_socket(sock, server_hostname=host) as ssock: return True, ssock.cipher()[0]
        except Exception: pass
    return False, None

def evaluate_sweet32_risk(record: Dict[str, Any]) -> str:
    if not record.get("tcp_connect"): return "NO-CONNECT"
    if not record.get("is_tls"): return "NO-TLS"
    if record.get("supports_3des") is True:
        if record.get("tls_supports_legacy") is True or record.get("tls_version") != "TLSv1.3": return "SWEET32-RISK"
        return "WEAK-3DES"
    if record.get("supports_3des") is None: return "UNKNOWN-3DES"
    return "OK"

def scan_host_port(host: str, port: int, timeout: float, proxy_mgr: Optional[ProxyRotationManager] = None) -> Dict[str, Any]:
    record = {"ts": datetime.utcnow().isoformat() + "Z", "host": host, "port": port, "tcp_connect": False, "is_tls": False, "tls_version": None, "tls_cipher": None, "tls_supports_legacy": None, "supports_3des": None, "three_des_cipher": None, "error": None}
    sock = tcp_connect(host, port, timeout, proxy_mgr)
    if not sock:
        record["error"] = "connect_failed"
        return record
    record["tcp_connect"] = True
    try:
        ok, version, cipher = tls_handshake_basic(host, sock)
        if not ok: record["error"] = "not_tls_or_handshake_failed"; return record
        record["is_tls"] = True; record["tls_version"] = version; record["tls_cipher"] = cipher
    finally:
        try: sock.close()
        except: pass
    record["tls_supports_legacy"] = tls_supports_legacy(host, port, timeout, proxy_mgr)
    supports_3des, three_des_cipher = tls_probe_3des(host, port, timeout, proxy_mgr)
    record["supports_3des"] = supports_3des; record["three_des_cipher"] = three_des_cipher
    return record

def parse_proxy_list(text: str, default_scheme: str = "SOCKS5") -> List[ProxyEndpoint]:
    endpoints = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"): continue
        m = _PROXY_LINE_RE.match(line)
        if not m: continue
        socks_proto, http_proto, host, port_s = m.group(1), m.group(2), m.group(3), m.group(4)
        port = int(port_s)
        if not (1 <= port <= 65535): continue
        scheme = "SOCKS5" if socks_proto else ("HTTP_CONNECT" if http_proto else default_scheme)
        endpoints.append(ProxyEndpoint(scheme=scheme, host=host, port=port))
    return endpoints

def proxy_health_check(ep: ProxyEndpoint, timeout: float = 3.0) -> ProxyEndpoint:
    start = time.time()
    try:
        sock = socket.create_connection((ep.host, ep.port), timeout=timeout); sock.close()
        ep.alive = True; ep.latency_ms = round((time.time() - start) * 1000, 1)
    except: ep.alive = False; ep.latency_ms = None
    return ep

def sort_endpoints(eps: List[ProxyEndpoint]) -> List[ProxyEndpoint]:
    return sorted(eps, key=lambda e: (not e.alive, e.latency_ms if e.latency_ms is not None else 999999, e.port, e.scheme, e.host))

def export_valid_pool_json(eps: List[ProxyEndpoint], path: str) -> None:
    data = [{"scheme": e.scheme, "host": e.host, "port": e.port, "latency_ms": e.latency_ms, "pinned": e.pinned} for e in eps if e.alive]
    with open(path, "w", encoding="utf-8") as f: json.dump(data, f, indent=2, sort_keys=True)


class RelayProtocolError(Exception): pass

def _recv_json_lines(sock: socket.socket):
    buf = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk: break
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            line = line.strip()
            if not line: continue
            try: yield json.loads(line.decode("utf-8", errors="replace"))
            except Exception as e: raise RelayProtocolError(f"Bad JSON line: {e}") from e

def _send_json_line(sock: socket.socket, obj: Dict[str, Any], lock: threading.Lock) -> None:
    data = (json.dumps(obj, separators=(",", ":"), sort_keys=False) + "\n").encode("utf-8")
    with lock: sock.sendall(data)

class RelayServer:
    def __init__(self, listen_host: str, listen_port: int, token: str = "", workers: int = 128):
        self.listen_host = listen_host; self.listen_port = listen_port; self.token = token or ""; self.workers = max(1, int(workers)); self._stop = threading.Event(); self._thread = None
    def start(self):
        if self._thread and self._thread.is_alive(): return
        self._stop.clear(); self._thread = threading.Thread(target=self._serve, daemon=True); self._thread.start()
        logger.info("Relay server listening on %s:%d", self.listen_host, self.listen_port)
    def stop(self): self._stop.set(); logger.info("Relay server stop requested")
    def _serve(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((self.listen_host, self.listen_port)); s.listen(5); s.settimeout(0.5)
            while not self._stop.is_set():
                try: conn, addr = s.accept(); threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
                except: continue
    def _handle_client(self, conn, addr):
        send_lock = threading.Lock(); task_q = queue.Queue(); cancel = threading.Event(); cfg_timeout = DEFAULT_TIMEOUT
        def worker():
            while not cancel.is_set():
                try: task = task_q.get(timeout=0.5)
                except: continue
                try:
                    rec = scan_host_port(task.host, task.port, cfg_timeout)
                    _send_json_line(conn, {"type": "result", "record": rec}, send_lock)
                except Exception as e: _send_json_line(conn, {"type": "worker_error", "error": str(e), "host": task.host, "port": task.port}, send_lock)
                finally: task_q.task_done()
        for _ in range(self.workers): threading.Thread(target=worker, daemon=True).start()
        try:
            conn.settimeout(10.0); reader = _recv_json_lines(conn); hello = next(reader, None)
            if not hello or hello.get("type") != "hello" or (self.token and hello.get("token") != self.token):
                _send_json_line(conn, {"type": "error", "error": "unauthorized"}, send_lock); return
            cfg_timeout = float(hello.get("timeout", DEFAULT_TIMEOUT))
            _send_json_line(conn, {"type": "hello_ack"}, send_lock)
            submitted = 0
            for msg in reader:
                if msg.get("type") == "task":
                    task_q.put(ScanTask(host=str(msg.get("host")), port=int(msg.get("port")))); submitted += 1
                elif msg.get("type") == "done": break
                elif msg.get("type") == "cancel": cancel.set(); break
            task_q.join(); cancel.set(); _send_json_line(conn, {"type": "complete", "submitted": submitted}, send_lock)
        except: pass
        finally: conn.close()

class RelayClient:
    def __init__(self, addr: str, token: str = ""): self.addr = addr; self.token = token or ""
    def run(self, tasks, timeout, cancel_event, on_record):
        h, p = self.addr.rsplit(":", 1); h, p = h.strip(), int(p)
        with socket.create_connection((h, p), timeout=10.0) as sock:
            send_lock = threading.Lock(); _send_json_line(sock, {"type": "hello", "token": self.token, "timeout": timeout}, send_lock)
            for msg in _recv_json_lines(sock):
                if msg.get("type") == "hello_ack": break
            for t in tasks:
                if cancel_event.is_set(): _send_json_line(sock, {"type": "cancel"}, send_lock); return
                _send_json_line(sock, {"type": "task", "host": t.host, "port": t.port}, send_lock)
            _send_json_line(sock, {"type": "done"}, send_lock)
            for msg in _recv_json_lines(sock):
                if cancel_event.is_set(): return
                if msg.get("type") == "result": on_record(msg.get("record"))
                elif msg.get("type") == "complete": return

class RateLimiter:
    def __init__(self, rate: int, per_seconds: float):
        self.rate = max(1, int(rate)); self.per = max(0.1, float(per_seconds)); self.tokens = float(self.rate); self.updated = time.monotonic(); self.lock = threading.Lock()
    def allow(self) -> bool:
        with self.lock:
            now = time.monotonic(); delta = now - self.updated; self.updated = now
            self.tokens = min(self.rate, self.tokens + delta * (self.rate / self.per))
            if self.tokens >= 1.0: self.tokens -= 1.0; return True
            return False

@dataclass
class ScanTask:
    host: str
    port: int
    attempts: int = 0

@dataclass
class ScanConfig:
    targets: List[str]; ports: List[int]; timeout: float; workers: int; outfile: str; verbose: bool = False; max_attempts: int = DEFAULT_MAX_ATTEMPTS; proxy_manager: Optional[ProxyRotationManager] = None; global_rate: int = 0; relay_enabled: bool = False; relay_addr: str = ""; relay_token: str = ""

class ScannerEngine:
    def __init__(self, config: ScanConfig, cancel_event: threading.Event, progress_callback: Optional[Callable[[int, int], None]] = None):
        self.config = config
        self.cancel_event = cancel_event
        self.progress_callback = progress_callback
        self._global_limiter = RateLimiter(self.config.global_rate, 1.0) if self.config.global_rate > 0 else None
        
        # Shared progress counter
        self._progress_lock = threading.Lock()
        self._tasks_completed = 0
        self._tasks_total = 0

    def run(self) -> None:
        if self.config.verbose: logger.setLevel(logging.DEBUG)
        
        logger.info("Expanding targets...")
        targets = expand_targets(self.config.targets)
        ports = sorted(set(self.config.ports))
        self._tasks_total = len(targets) * len(ports)
        logger.info("Total tasks to scan: %d", self._tasks_total)
        
        if self.progress_callback:
            self.progress_callback(0, self._tasks_total)

        tasks = [ScanTask(h, p) for h in targets for p in ports]
        
        out_lock = threading.Lock()
        with open(self.config.outfile, "a", encoding="utf-8") as out_f:
            def _log_and_write(rec):
                with out_lock: out_f.write(json.dumps(rec, sort_keys=True) + "\n"); out_f.flush()
                with self._progress_lock: self._tasks_completed += 1
                st = evaluate_sweet32_risk(rec)
                if rec.get("tcp_connect") and rec.get("is_tls"):
                    lvl = logging.WARNING if st in ("SWEET32-RISK", "WEAK-3DES") else logging.INFO
                    logger.log(lvl, "[%s] %s:%d %s", st, rec.get("host"), rec.get("port"), rec.get("tls_cipher"))
                else: logger.info("[%s] %s:%d (%s)", st, rec.get("host"), rec.get("port"), rec.get("error") or "no_connect")
            
            if self.config.relay_enabled:
                RelayClient(self.config.relay_addr, token=self.config.relay_token).run(tasks, self.config.timeout, self.cancel_event, _log_and_write)
                with self._progress_lock: self._tasks_completed = self._tasks_total
                return
            
            task_q = queue.Queue()
            for t in tasks: task_q.put(t)
            
            def _worker():
                while not self.cancel_event.is_set():
                    try: t = task_q.get(timeout=0.5)
                    except: return
                    try:
                        if self._global_limiter and not self._global_limiter.allow(): task_q.put(t); continue
                        _log_and_write(scan_host_port(t.host, t.port, self.config.timeout, self.config.proxy_manager))
                    except: t.attempts+=1; task_q.put(t) if t.attempts < self.config.max_attempts else None
                    finally: task_q.task_done()
            
            for _ in range(self.config.workers): threading.Thread(target=_worker, daemon=True).start()
            while not self.cancel_event.is_set() and task_q.unfinished_tasks > 0: 
                time.sleep(0.5)
                if self.progress_callback: self.progress_callback(self._tasks_completed, self._tasks_total)
            try: task_q.join()
            except: pass
            if self.progress_callback: self.progress_callback(self._tasks_completed, self._tasks_total)


# -------------------------
# GUI
# -------------------------

class ScannerGUI:
    def __init__(self) -> None:
        if tk is None: raise RuntimeError("Tkinter not available")
        self.root = tk.Tk()
        self.root.title("[ R0ck-S4alt:WS-Man ] Scanner (By:xC4)")
        self.root.geometry(GUI_GEOMETRY)
        self.root.configure(bg=UI_BG_MAIN)
        self.cancel_event = threading.Event()
        self.scan_log_q = queue.Queue(); self.debug_log_q = queue.Queue()
        self._endpoints = []; self._endpoints_lock = threading.Lock()
        self._relay_server = None
        self._install_gui_logging()
        self._setup_ttk_style()
        
        # Progress Tracking Vars
        self.current_engine = None 
        self.scan_running = False

        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill="both", expand=True)
        self.scan_tab = tk.Frame(self.tabs, bg=UI_BG_MAIN)
        self.conn_tab = tk.Frame(self.tabs, bg=UI_BG_MAIN)
        self.sett_tab = tk.Frame(self.tabs, bg=UI_BG_MAIN)
        self.rock_tab = tk.Frame(self.tabs, bg=UI_BG_MAIN) # ROCK TAB

        self.tabs.add(self.scan_tab, text="Scan")
        self.tabs.add(self.conn_tab, text="Connections")
        self.tabs.add(self.sett_tab, text="Settings")
        self.tabs.add(self.rock_tab, text="Rock") # ROCK LABEL

        self._build_controls(self.scan_tab)
        self._build_logs(self.scan_tab)
        self._build_connections_tab(self.conn_tab)
        self._build_settings_tab(self.sett_tab)
        self._build_rock_tab(self.rock_tab) # Build Rock Tab
        
        self._poll_logs()
        self._update_progress_ui()

    def _setup_ttk_style(self):
        style = ttk.Style()
        style.theme_use(UI_TTK_THEME)
        style.configure("TNotebook", background=UI_BG_MAIN, borderwidth=0)
        style.configure("TNotebook.Tab", background=UI_TAB_BG, foreground=UI_TAB_FG, padding=[10, 2])
        style.map("TNotebook.Tab", background=[("selected", UI_TAB_SELECTED_BG)], foreground=[("selected", UI_TAB_SELECTED_FG)])
        style.configure("TCombobox", fieldbackground=UI_ENTRY_BG, background=UI_BTN_BG, foreground=UI_ENTRY_FG, arrowcolor=UI_FG_MAIN)
        style.map("TCombobox", fieldbackground=[("readonly", UI_ENTRY_BG)], selectbackground=[("readonly", UI_SELECT_BG)], selectforeground=[("readonly", UI_SELECT_FG)])
        style.configure("Horizontal.TProgressbar", background=UI_PROGRESS_BG, troughcolor=UI_PROGRESS_TROUGH, bordercolor=UI_BG_MAIN, lightcolor=UI_PROGRESS_BG, darkcolor=UI_PROGRESS_BG)

    def _install_gui_logging(self) -> None:
        logger.handlers = [h for h in logger.handlers if not isinstance(h, TkQueueHandler)]
        for q, lvl in [(self.scan_log_q, logging.INFO), (self.debug_log_q, logging.DEBUG)]:
            h = TkQueueHandler(q); h.setLevel(lvl); h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s")); logger.addHandler(h)

    def _make_button(self, parent, text, command, bg=UI_BTN_BG, fg=UI_BTN_FG, active_bg=UI_BTN_ACTIVE_BG, active_fg=UI_BTN_ACTIVE_FG):
        """Creates a styled, interactive button."""
        return tk.Button(parent, text=text, command=command, bg=bg, fg=fg, 
                         activebackground=active_bg, activeforeground=active_fg, 
                         font=("Courier", 11, "bold"), relief=UI_BTN_RELIEF, bd=UI_BTN_BORDER,
                         cursor="hand2")

    def _make_entry(self, parent, width, show=None):
        return tk.Entry(parent, width=width, bg=UI_ENTRY_BG, fg=UI_ENTRY_FG, insertbackground=UI_CURSOR_COLOR, selectbackground=UI_SELECT_BG, selectforeground=UI_SELECT_FG, font=("Courier", 10), show=show)

    def _make_check(self, parent, text, var):
        return tk.Checkbutton(parent, text=text, variable=var, bg=UI_CHK_BG, fg=UI_CHK_FG, selectcolor=UI_CHK_SELECT_COLOR, activebackground=UI_CHK_ACTIVE_BG, activeforeground=UI_CHK_ACTIVE_FG)

    # --- MAIN SCAN TAB ---
    def _build_controls(self, parent):
        top = tk.Frame(parent, bg=UI_BG_MAIN); top.pack(fill="x", padx=12, pady=10)
        tk.Label(top, text="Targets (one per line)", bg=UI_BG_MAIN, fg=UI_FG_MAIN).grid(row=0, column=0, sticky="w")
        self.targets_text = scrolledtext.ScrolledText(top, width=58, height=6, bg=UI_ENTRY_BG, fg=UI_ENTRY_FG, font=("Courier", 10), insertbackground=UI_CURSOR_COLOR, selectbackground=UI_SELECT_BG, selectforeground=UI_SELECT_FG)
        self.targets_text.grid(row=1, column=0, rowspan=7, sticky="we", padx=(0, 12)); self.targets_text.insert("1.0", "10.0.0.0/24")

        settings = tk.Frame(top, bg=UI_BG_MAIN); settings.grid(row=1, column=1, sticky="n")
        tk.Label(settings, text="Ports", bg=UI_BG_MAIN, fg=UI_FG_MAIN).pack(anchor="w")
        self.ports_entry = self._make_entry(settings, 34); self.ports_entry.pack(anchor="w"); self.ports_entry.insert(0, " ".join(str(p) for p in DEFAULT_PORTS))

        tk.Label(settings, text="Timeout / Workers / Attempts", bg=UI_BG_MAIN, fg=UI_FG_MAIN).pack(anchor="w", pady=(10, 0))
        row_conf = tk.Frame(settings, bg=UI_BG_MAIN); row_conf.pack(anchor="w")
        self.timeout_entry = self._make_entry(row_conf, 6); self.timeout_entry.pack(side="left"); self.timeout_entry.insert(0, str(DEFAULT_TIMEOUT))
        self.workers_spin = tk.Spinbox(row_conf, from_=1, to=4096, width=6, bg=UI_ENTRY_BG, fg=UI_ENTRY_FG, buttonbackground=UI_SPIN_ARROW_BG); self.workers_spin.pack(side="left", padx=5); self.workers_spin.insert(0, str(DEFAULT_WORKERS))
        self.max_attempts_spin = tk.Spinbox(row_conf, from_=1, to=20, width=6, bg=UI_ENTRY_BG, fg=UI_ENTRY_FG, buttonbackground=UI_SPIN_ARROW_BG); self.max_attempts_spin.pack(side="left"); self.max_attempts_spin.insert(0, str(DEFAULT_MAX_ATTEMPTS))

        self.verbose_var = tk.BooleanVar(value=False); self.use_pool_var = tk.BooleanVar(value=False); self.relay_enabled_var = tk.BooleanVar(value=False)
        self._make_check(settings, "Verbose", self.verbose_var).pack(anchor="w", pady=(5,0))
        self._make_check(settings, "Use Connection Pool", self.use_pool_var).pack(anchor="w")
        self._make_check(settings, "Use Relay Agent", self.relay_enabled_var).pack(anchor="w")

        r_row = tk.Frame(settings, bg=UI_BG_MAIN); r_row.pack(anchor="w", fill="x", pady=(4, 0))
        self.relay_addr_entry = self._make_entry(r_row, 14); self.relay_addr_entry.pack(side="left"); self.relay_addr_entry.insert(0, DEFAULT_RELAY_ADDR)
        self.relay_token_entry = self._make_entry(r_row, 14, show="*"); self.relay_token_entry.pack(side="left", padx=5)

        o_row = tk.Frame(settings, bg=UI_BG_MAIN); o_row.pack(anchor="w", fill="x", pady=10)
        self.outfile_entry = self._make_entry(o_row, 22); self.outfile_entry.pack(side="left"); self.outfile_entry.insert(0, DEFAULT_OUTFILE)
        self._make_button(o_row, "Browse", self._browse_outfile).pack(side="left", padx=5)

        btns = tk.Frame(top, bg=UI_BG_MAIN); btns.grid(row=9, column=0, columnspan=2, sticky="we", pady=(10, 0))
        self.start_btn = self._make_button(btns, "Start Scan", self.start_scan); self.start_btn.pack(side="left")
        self.cancel_btn = self._make_button(btns, "Cancel", self.cancel_scan, bg=UI_BTN_CANCEL_BG, fg=UI_BTN_CANCEL_FG, active_bg=UI_BTN_CANCEL_ACTIVE_BG, active_fg=UI_BTN_CANCEL_ACTIVE_FG); self.cancel_btn.pack(side="left", padx=10); self.cancel_btn.configure(state="disabled")
        self._make_button(btns, "Clear Logs", self.clear_logs).pack(side="left")

        prog_frame = tk.Frame(top, bg=UI_BG_MAIN); prog_frame.grid(row=10, column=0, columnspan=2, sticky="we", pady=(15, 0))
        self.progress_bar = ttk.Progressbar(prog_frame, orient="horizontal", mode="determinate", style="Horizontal.TProgressbar"); self.progress_bar.pack(fill="x", expand=True, side="left")
        self.progress_lbl = tk.Label(prog_frame, text="Ready", bg=UI_BG_MAIN, fg=UI_FG_MAIN, font=("Courier", 10)); self.progress_lbl.pack(side="left", padx=(10, 0))

    def _build_logs(self, parent):
        logs = tk.Frame(parent, bg=UI_BG_MAIN); logs.pack(fill="both", expand=True, padx=12, pady=10)
        tk.Label(logs, text="Scan Output", bg=UI_BG_MAIN, fg=UI_FG_MAIN).pack(anchor="w")
        self.scan_output = scrolledtext.ScrolledText(logs, height=14, bg=UI_BG_PANE, fg=UI_FG_MAIN, font=("Courier", 10), insertbackground=UI_CURSOR_COLOR); self.scan_output.pack(fill="both", expand=True)
        tk.Label(logs, text="Debug", bg=UI_BG_MAIN, fg=UI_FG_MAIN).pack(anchor="w", pady=(10, 0))
        self.debug_output = scrolledtext.ScrolledText(logs, height=8, bg=UI_BG_PANE, fg=UI_FG_MAIN, font=("Courier", 10), insertbackground=UI_CURSOR_COLOR); self.debug_output.pack(fill="both", expand=False)

    def _build_connections_tab(self, parent):
        frame = tk.Frame(parent, bg=UI_BG_MAIN); frame.pack(fill="both", expand=True, padx=12, pady=10)
        left = tk.Frame(frame, bg=UI_BG_MAIN); right = tk.Frame(frame, bg=UI_BG_MAIN)
        left.pack(side="left", fill="both", expand=True, padx=(0, 10)); right.pack(side="left", fill="both", expand=True)
        tk.Label(left, text="Proxy List", bg=UI_BG_MAIN, fg=UI_FG_MAIN).pack(anchor="w")
        self.proxies_text = scrolledtext.ScrolledText(left, height=14, bg=UI_ENTRY_BG, fg=UI_ENTRY_FG, font=("Courier", 10), insertbackground=UI_CURSOR_COLOR); self.proxies_text.pack(fill="both", expand=True); self.proxies_text.insert("1.0", "# Socks5://127.0.0.1:1080\n")
        b_row = tk.Frame(left, bg=UI_BG_MAIN); b_row.pack(fill="x", pady=8)
        self._make_button(b_row, "Health Check", self.health_check).pack(side="left")
        self._make_button(b_row, "Save List", self.save_proxies_list).pack(side="left", padx=5)
        self._make_button(b_row, "Clear", lambda: self.proxies_text.delete("1.0", "end")).pack(side="left", padx=5)
        o_row = tk.Frame(left, bg=UI_BG_MAIN); o_row.pack(fill="x")
        self.default_scheme_var = tk.StringVar(value="SOCKS5"); ttk.Combobox(o_row, textvariable=self.default_scheme_var, values=["SOCKS5", "HTTP_CONNECT"], width=10).pack(side="left")
        tk.Label(right, text="Valid Pool (Right-click to PIN)", bg=UI_BG_MAIN, fg=UI_FG_MAIN).pack(anchor="w")
        self.valid_list = tk.Listbox(right, height=10, bg=UI_LIST_BG, fg=UI_LIST_FG, selectbackground=UI_LIST_SELECT_BG, selectforeground=UI_LIST_SELECT_FG); self.valid_list.pack(fill="both"); self.valid_list.bind("<Button-3>", self._toggle_pin)
        self.valid_stats_lbl = tk.Label(right, text="Total: 0", bg=UI_BG_MAIN, fg=UI_FG_MAIN); self.valid_stats_lbl.pack(anchor="w")
        self._make_button(right, "Export JSON", self.export_valid_pool).pack(anchor="w", pady=5)
        tk.Label(right, text="Relay Server", bg=UI_BG_MAIN, fg=UI_FG_MAIN).pack(anchor="w", pady=(10,0))
        srv_row = tk.Frame(right, bg=UI_BG_MAIN); srv_row.pack(fill="x")
        self.relay_listen_entry = self._make_entry(srv_row, 18); self.relay_listen_entry.pack(side="left"); self.relay_listen_entry.insert(0, DEFAULT_RELAY_LISTEN)
        self._make_button(srv_row, "Start", self.start_relay_server).pack(side="left", padx=5)
        self._make_button(srv_row, "Stop", self.stop_relay_server).pack(side="left")
        tk.Label(right, text="Connection Pool Snapshot", bg=UI_BG_MAIN, fg=UI_FG_MAIN).pack(anchor="w", pady=(12, 0))
        self.pool_snapshot = scrolledtext.ScrolledText(right, height=12, bg=UI_BG_PANE, fg=UI_FG_MAIN, font=("Courier", 10), insertbackground=UI_CURSOR_COLOR); self.pool_snapshot.pack(fill="both", expand=True)

    def _build_settings_tab(self, parent):
        frame = tk.Frame(parent, bg=UI_BG_MAIN); frame.pack(fill="both", expand=True, padx=12, pady=10)
        tk.Label(frame, text="I2P Configuration (SAM Bridge)", bg=UI_BG_MAIN, fg=UI_FG_MAIN, font=("Courier", 11, "bold")).pack(anchor="w", pady=(0, 10))
        sam_row = tk.Frame(frame, bg=UI_BG_MAIN); sam_row.pack(fill="x", anchor="w")
        tk.Label(sam_row, text="SAM Host:", bg=UI_BG_MAIN, fg=UI_FG_MAIN).pack(side="left")
        self.sam_host_entry = self._make_entry(sam_row, 15); self.sam_host_entry.pack(side="left", padx=5); self.sam_host_entry.insert(0, DEFAULT_SAM_HOST)
        tk.Label(sam_row, text="Port:", bg=UI_BG_MAIN, fg=UI_FG_MAIN).pack(side="left", padx=5)
        self.sam_port_entry = self._make_entry(sam_row, 6); self.sam_port_entry.pack(side="left", padx=5); self.sam_port_entry.insert(0, str(DEFAULT_SAM_PORT))
        
        # SOCKS TUNNEL CONFIG
        tk.Label(frame, text="SOCKS5 Tunnel Config (9001)", bg=UI_BG_MAIN, fg=UI_FG_MAIN, font=("Courier", 11, "bold")).pack(anchor="w", pady=(20, 10))
        tun_row = tk.Frame(frame, bg=UI_BG_MAIN); tun_row.pack(fill="x", anchor="w")
        tk.Label(tun_row, text="Host:", bg=UI_BG_MAIN, fg=UI_FG_MAIN).pack(side="left")
        self.socks_host_entry = self._make_entry(tun_row, 15); self.socks_host_entry.pack(side="left", padx=5); self.socks_host_entry.insert(0, "127.0.0.1")
        tk.Label(tun_row, text="Port:", bg=UI_BG_MAIN, fg=UI_FG_MAIN).pack(side="left", padx=5)
        self.socks_port_entry = self._make_entry(tun_row, 6); self.socks_port_entry.pack(side="left", padx=5); self.socks_port_entry.insert(0, "9001")
        self._make_button(tun_row, "Inject & Activate", self.inject_socks_tunnel).pack(side="left", padx=15)

        if not I2P_AVAILABLE: tk.Label(frame, text="[!] 'i2plib' not installed. I2P features disabled.", bg=UI_BG_MAIN, fg="#ff4444").pack(anchor="w", pady=10); return
        tk.Label(frame, text="I2P Server", bg=UI_BG_MAIN, fg=UI_FG_MAIN, font=("Courier", 11, "bold")).pack(anchor="w", pady=(20, 10))
        self._make_button(frame, "Start Hosting Service", self.start_i2p_server_thread).pack(anchor="w")
        tk.Label(frame, text="Your I2P Destination:", bg=UI_BG_MAIN, fg=UI_FG_MAIN).pack(anchor="w", pady=(5,0))
        self.i2p_dest_display = self._make_entry(frame, 60); self.i2p_dest_display.pack(anchor="w")
        tk.Label(frame, text="I2P Client", bg=UI_BG_MAIN, fg=UI_FG_MAIN, font=("Courier", 11, "bold")).pack(anchor="w", pady=(20, 10))
        client_row = tk.Frame(frame, bg=UI_BG_MAIN); client_row.pack(fill="x", anchor="w")
        tk.Label(client_row, text="Dest (.b32.i2p):", bg=UI_BG_MAIN, fg=UI_FG_MAIN).pack(side="left")
        self.i2p_client_dest_entry = self._make_entry(client_row, 45); self.i2p_client_dest_entry.pack(side="left", padx=5)
        self._make_button(client_row, "Connect & Send Hello", self.connect_i2p_client_thread).pack(side="left", padx=5)

    def inject_socks_tunnel(self):
        h = self.socks_host_entry.get().strip(); p = self.socks_port_entry.get().strip()
        if not h or not p: return
        line = f"socks5://{h}:{p}\n"; self.proxies_text.insert("1.0", line)
        
        # Verify and Pin immediately
        def _verify():
            try:
                ep = ProxyEndpoint("SOCKS5", h, int(p))
                ep = proxy_health_check(ep, 2.0)
                if ep.alive:
                    ep.pinned = True
                    with self._endpoints_lock:
                        # Clear pinned status from others to enforce single tunnel if desired, or just add
                        for e in self._endpoints: e.pinned = False
                        self._endpoints.insert(0, ep)
                    self.root.after(0, self._refresh_valid_lists)
                    messagebox.showinfo("Success", f"Tunnel {h}:{p} is ALIVE and Pinned.")
                else:
                    messagebox.showwarning("Failed", f"Tunnel {h}:{p} is NOT reachable.")
            except Exception as e: messagebox.showerror("Error", str(e))
        threading.Thread(target=_verify, daemon=True).start()

    # --- ROCK TAB (Project RockSalt.py) ---
    def _build_rock_tab(self, parent):
        frame = tk.Frame(parent, bg=UI_BG_MAIN); frame.pack(fill="both", expand=True, padx=12, pady=10)
        
        # --- Top: Nmap Scan ---
        tk.Label(frame, text="Project RockSalt.py - Single Target Scan", bg=UI_BG_MAIN, fg=UI_FG_MAIN, font=("Courier", 12, "bold")).pack(anchor="w", pady=(0,10))
        
        n_row = tk.Frame(frame, bg=UI_BG_MAIN); n_row.pack(fill="x", anchor="w")
        tk.Label(n_row, text="Target IP:", bg=UI_BG_MAIN, fg=UI_FG_MAIN).pack(side="left")
        self.rock_target = self._make_entry(n_row, 20); self.rock_target.pack(side="left", padx=5)
        tk.Label(n_row, text="Args:", bg=UI_BG_MAIN, fg=UI_FG_MAIN).pack(side="left", padx=5)
        self.rock_args = self._make_entry(n_row, 25); self.rock_args.pack(side="left", padx=5); self.rock_args.insert(0, "-sV -O")
        self._make_button(n_row, "Scan (Nmap)", self.run_rock_scan).pack(side="left", padx=10)
        
        self.rock_output = scrolledtext.ScrolledText(frame, height=12, bg=UI_BG_PANE, fg=UI_FG_MAIN, font=("Courier", 10), insertbackground=UI_CURSOR_COLOR); self.rock_output.pack(fill="both", expand=True, pady=10)
        if not NMAP_AVAILABLE: self.rock_output.insert("end", "[!] python-nmap not installed or nmap binary missing.\n")

        # --- Bottom: Connect Launcher ---
        tk.Label(frame, text="Shell / Connection Launcher", bg=UI_BG_MAIN, fg=UI_FG_MAIN, font=("Courier", 12, "bold")).pack(anchor="w", pady=(10,5))
        
        c_row = tk.Frame(frame, bg=UI_BG_MAIN); c_row.pack(fill="x", anchor="w")
        
        tk.Label(c_row, text="Tool:", bg=UI_BG_MAIN, fg=UI_FG_MAIN).pack(side="left")
        self.rock_tool_var = tk.StringVar(value="nc"); ttk.Combobox(c_row, textvariable=self.rock_tool_var, values=["nc", "ncat", "pwncat", "ssh"], width=8).pack(side="left", padx=5)
        
        tk.Label(c_row, text="Target:", bg=UI_BG_MAIN, fg=UI_FG_MAIN).pack(side="left", padx=5)
        self.rock_conn_ip = self._make_entry(c_row, 15); self.rock_conn_ip.pack(side="left")
        
        tk.Label(c_row, text="Port:", bg=UI_BG_MAIN, fg=UI_FG_MAIN).pack(side="left", padx=5)
        self.rock_conn_port = self._make_entry(c_row, 6); self.rock_conn_port.pack(side="left")
        
        tk.Label(c_row, text="User/Pass (SSH):", bg=UI_BG_MAIN, fg=UI_FG_MAIN).pack(side="left", padx=5)
        self.rock_conn_user = self._make_entry(c_row, 12); self.rock_conn_user.pack(side="left")
        
        self._make_button(c_row, "Launch Terminal", self.launch_rock_connection).pack(side="left", padx=15)

    def run_rock_scan(self):
        if not NMAP_AVAILABLE: return
        target = self.rock_target.get().strip(); args = self.rock_args.get().strip()
        if not target: return
        self.rock_output.insert("end", f"\n[*] Starting Scan: {target} {args}\n"); self.rock_output.see("end")
        def _scan():
            try:
                nm = nmap.PortScanner()
                nm.scan(target, arguments=args)
                for host in nm.all_hosts():
                    out = f"\nHost: {host} ({nm[host].hostname()})\nState: {nm[host].state()}\n"
                    for proto in nm[host].all_protocols():
                        out += f"Protocol: {proto}\n"
                        lport = sorted(nm[host][proto].keys())
                        for port in lport:
                            out += f"  port: {port}\tstate: {nm[host][proto][port]['state']}\tname: {nm[host][proto][port]['name']}\n"
                    self.rock_output.insert("end", out)
            except Exception as e:
                self.rock_output.insert("end", f"\n[!] Scan Error: {e}\n")
            self.rock_output.see("end")
        threading.Thread(target=_scan, daemon=True).start()

    def launch_rock_connection(self):
        tool = self.rock_tool_var.get()
        ip = self.rock_conn_ip.get().strip()
        port = self.rock_conn_port.get().strip()
        user = self.rock_conn_user.get().strip() 
        
        if not ip or not port: return
        
        cmd_str = ""
        if tool == "nc": cmd_str = f"nc {ip} {port}"
        elif tool == "ncat": cmd_str = f"ncat -v {ip} {port}"
        elif tool == "pwncat": cmd_str = f"pwncat-cs {ip} {port}" 
        elif tool == "ssh":
            target = f"{user}@{ip}" if user else ip
            cmd_str = f"ssh {target} -p {port}"

        # Launch in system terminal
        system = platform.system()
        try:
            if system == "Windows":
                subprocess.Popen(f"start cmd /k {cmd_str}", shell=True)
            elif system == "Linux":
                terms = ["gnome-terminal", "xterm", "konsole", "xfce4-terminal"]
                launched = False
                for t in terms:
                    if os.system(f"which {t} > /dev/null 2>&1") == 0:
                        if t == "gnome-terminal": subprocess.Popen([t, "--", "bash", "-c", f"{cmd_str}; exec bash"])
                        else: subprocess.Popen([t, "-e", f"{cmd_str}; bash"])
                        launched = True; break
                if not launched: messagebox.showerror("Error", "No compatible terminal emulator found.")
            elif system == "Darwin": # MacOS
                subprocess.Popen(["osascript", "-e", f'tell app "Terminal" to do script "{cmd_str}"'])
        except Exception as e:
            messagebox.showerror("Launch Error", str(e))

    # --- I2P Logic ---
    def start_i2p_server_thread(self):
        if not I2P_AVAILABLE: return
        threading.Thread(target=self._run_i2p_server_async, daemon=True).start()

    def _run_i2p_server_async(self):
        asyncio.run(self._i2p_server_logic())

    async def _i2p_server_logic(self):
        sam_host = self.sam_host_entry.get(); sam_port = int(self.sam_port_entry.get())
        logger.info(f"Starting I2P Server via SAM {sam_host}:{sam_port}...")
        
        async def handle_client(reader, writer):
            dest = await reader.readline()
            logger.info(f"I2P Server: Connection from {dest.decode().strip()[:20]}...")
            writer.write(b"PONG\n")
            await writer.drain()
            writer.close()
        
        try:
            session_name = "server-session"
            session = await i2plib.create_session(session_name, sam_address=(sam_host, sam_port))
            my_dest = session.destination.base32 + ".b32.i2p"
            logger.info(f"I2P Service Running: {my_dest}")
            self.i2p_dest_display.delete(0, "end"); self.i2p_dest_display.insert(0, my_dest)
            await i2plib.stream_accept(session_name, handle_client, sam_address=(sam_host, sam_port))
        except Exception as e:
            logger.error(f"I2P Server Error: {e}")

    def connect_i2p_client_thread(self):
        if not I2P_AVAILABLE: return
        dest = self.i2p_client_dest_entry.get().strip()
        if not dest: return
        threading.Thread(target=self._run_i2p_client_async, args=(dest,), daemon=True).start()

    def _run_i2p_client_async(self, dest):
        asyncio.run(self._i2p_client_logic(dest))

    async def _i2p_client_logic(self, dest):
        sam_host = self.sam_host_entry.get(); sam_port = int(self.sam_port_entry.get())
        logger.info(f"Connecting to {dest} via I2P...")
        try:
            session_name = "client-session"
            await i2plib.create_session(session_name, sam_address=(sam_host, sam_port))
            reader, writer = await i2plib.stream_connect(session_name, dest, sam_address=(sam_host, sam_port))
            writer.write(b"Hello from Python Client!\n")
            await writer.drain()
            resp = await reader.read(1024)
            logger.info(f"I2P Received: {resp.decode()}")
            writer.close()
            await i2plib.destroy_session(session_name, sam_address=(sam_host, sam_port))
        except Exception as e:
            logger.error(f"I2P Client Error: {e}")

    # --- Other UI Logic ---
    def save_proxies_list(self):
        p = filedialog.asksaveasfilename(defaultextension=".txt", title="Save Proxy List", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if p:
            try:
                content = self.proxies_text.get("1.0", "end-1c"); 
                with open(p, "w", encoding="utf-8") as f: f.write(content)
                messagebox.showinfo("Saved", f"Proxy list saved to {p}")
            except Exception as e: messagebox.showerror("Error", f"Failed to save file: {e}")

    def _toggle_pin(self, _):
        sel = self.valid_list.curselection()
        if not sel: return
        with self._endpoints_lock:
            valid = [e for e in self._endpoints if e.alive]
            if int(sel[0]) < len(valid):
                ep = valid[int(sel[0])]; ep.pinned = not ep.pinned
                if ep.pinned:
                    for o in valid: 
                        if o is not ep: o.pinned = False
        self._refresh_valid_lists()

    def _browse_outfile(self):
        p = filedialog.asksaveasfilename(defaultextension=".jsonl"); self.outfile_entry.delete(0, "end"); self.outfile_entry.insert(0, p) if p else None

    def clear_logs(self): self.scan_output.delete("1.0", "end"); self.debug_output.delete("1.0", "end")

    def _poll_logs(self):
        self._drain(self.scan_log_q, self.scan_output, True); self._drain(self.debug_log_q, self.debug_output, False); self.root.after(100, self._poll_logs)

    def _drain(self, q, w, info):
        while True:
            try: l, m = q.get_nowait()
            except: break
            if info and l < logging.INFO: continue
            w.insert("end", m + "\n"); w.see("end")
    
    def _update_progress_ui(self):
        if self.current_engine and self.scan_running:
            cur = self.current_engine._tasks_completed; tot = self.current_engine._tasks_total
            pct = int((cur / tot) * 100) if tot > 0 else 0
            self.progress_bar["value"] = pct; self.progress_lbl.configure(text=f"{cur} / {tot} ({pct}%)")
        self.root.after(200, self._update_progress_ui)

    def _read_config(self) -> Optional[ScanConfig]:
        try:
            pool = None
            if self.use_pool_var.get():
                with self._endpoints_lock: alive = [e for e in self._endpoints if e.alive]; pool = [e for e in alive if e.pinned] or alive
                if not pool: raise ValueError("No healthy proxies")
            return ScanConfig(
                targets=self.targets_text.get("1.0", "end").splitlines(),
                ports=[int(p) for p in self.ports_entry.get().replace(",", " ").split()],
                timeout=float(self.timeout_entry.get()),
                workers=int(self.workers_spin.get()),
                outfile=self.outfile_entry.get().strip(),
                verbose=self.verbose_var.get(),
                max_attempts=int(self.max_attempts_spin.get()),
                proxy_manager=ProxyRotationManager(pool) if pool else None,
                relay_enabled=self.relay_enabled_var.get(),
                relay_addr=self.relay_addr_entry.get().strip(),
                relay_token=self.relay_token_entry.get().strip()
            )
        except Exception as e: messagebox.showerror("Error", str(e)); return None

    def start_scan(self):
        cfg = self._read_config()
        if not cfg: return
        self.cancel_event.clear(); self.start_btn.configure(state="disabled"); self.cancel_btn.configure(state="normal")
        self.progress_bar["value"] = 0; self.progress_lbl.configure(text="Initializing..."); self.scan_running = True
        
        def run_wrap():
            try:
                self.current_engine = ScannerEngine(cfg, self.cancel_event); self.current_engine.run()
            except Exception as e: logger.error("Fatal error: %s", e)
            finally: self.root.after(0, self._scan_finished)
        threading.Thread(target=run_wrap, daemon=True).start()

    def _scan_finished(self): 
        self.scan_running = False; self.start_btn.configure(state="normal"); self.cancel_btn.configure(state="disabled")
        self.progress_lbl.configure(text="Done"); self.progress_bar["value"] = 100

    def cancel_scan(self): self.cancel_event.set()

    def health_check(self):
        raw = self.proxies_text.get("1.0", "end"); eps = parse_proxy_list(raw, self.default_scheme_var.get())
        def _run():
            res = []
            with concurrent.futures.ThreadPoolExecutor(64) as ex:
                for f in concurrent.futures.as_completed([ex.submit(proxy_health_check, e) for e in eps]): res.append(f.result())
            with self._endpoints_lock: self._endpoints = sort_endpoints(res)
            self.root.after(0, self._refresh_valid_lists)
        threading.Thread(target=_run, daemon=True).start()

    def _refresh_valid_lists(self):
        with self._endpoints_lock: eps = self._endpoints
        alive = [e for e in eps if e.alive]
        self.valid_list.delete(0, "end")
        for e in alive: self.valid_list.insert("end", f"{e.key()} ({e.latency_ms}ms) {'[PIN]' if e.pinned else ''}")
        self.valid_stats_lbl.configure(text=f"Total: {len(eps)}  Alive: {len(alive)}")

    def export_valid_pool(self):
        p = filedialog.asksaveasfilename(defaultextension=".json"); export_valid_pool_json(self._endpoints, p) if p else None

    def start_relay_server(self):
        if not self._relay_server: 
            h, p = self.relay_listen_entry.get().rsplit(":", 1)
            self._relay_server = RelayServer(h, int(p))
        self._relay_server.start()
    def stop_relay_server(self): self._relay_server.stop() if self._relay_server else None

def main():
    if len(sys.argv) > 1:
        # CLI Mode
        return 0
    ScannerGUI().root.mainloop()

if __name__ == "__main__": main()
