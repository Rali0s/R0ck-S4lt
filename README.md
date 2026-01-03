# RockSalt v4 🧂🪨

**Defensive TLS Capability Probe, Proxy Manager & Multi-Tool**

RockSalt is a robust, multi-threaded GUI application designed for security professionals and network engineers. It combines deep TLS/SSL inspection (specifically for WSMAN/WinRM ports) with advanced proxy management (SOCKS/HTTP/I2P) and integrated network reconnaissance tools.

It features a custom **"Red Cypher"** dark theme and integrates directly with system tools like Nmap, Netcat, and SSH.

![RockSalt GUI](https://github.com/Rali0s/R0ck-S4lt/blob/main/rocksalt.png)

Coded By: 'Rek0n'

---

## 🚀 Key Features

* **⚡ Multi-Threaded TLS Scanner:**
    * Probes common ports (WinRM 5985/5986, SMB 445, etc.) for SSL/TLS capabilities.
    * **Vulnerability Detection:** Identifies weak ciphers, legacy SSL versions, and **Sweet32/3DES** susceptibility.
    * High-performance concurrent scanning with customizable worker threads.

* **🛡️ Advanced Proxy Management:**
    * **Round-Robin Rotation:** Automatically rotates through a pool of SOCKS5/HTTP proxies for outgoing connections.
    * **Health Checks:** Live latency and connectivity testing for proxy lists.
    * **Tunnel Injection:** Quickly inject a local SOCKS5 tunnel (default port 9001) and "Pin" it as the primary connection.

* **🧅 I2P Integration (Invisible Internet Project):**
    * **SAM Bridge Support:** Connects via local SAM bridge (default 127.0.0.1:7656).
    * **Hidden Services:** Spin up ephemeral I2P Servers (Receiver) directly from the GUI.
    * **Client Mode:** Send messages to `.b32.i2p` destinations anonymously.

* **🪨 Project RockSalt Tab:**
    * **Nmap GUI Wrapper:** Run asynchronous Nmap scans without freezing the interface.
    * **Shell Launcher:** One-click terminal spawning for `nc`, `ncat`, `pwncat`, and `ssh`.

* **🎨 Custom UI:**
    * "Red Cypher" High-Contrast Dark Theme.
    * Real-time Scan Progress Bar and logging panes.

---

## 🛠️ Prerequisites

### System Requirements
* **Python:** 3.8 or higher.
* **External Tools:** To use the "Rock" tab features, ensure the following are installed and in your system PATH:
    * `nmap`
    * `nc` (netcat) or `ncat`
    * `ssh`

### Python Dependencies
Install the required libraries:

```bash
pip install -r requirements.txt
