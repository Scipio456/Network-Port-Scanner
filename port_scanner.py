"""
Ethical Local Network Port Scanner (Educational)

DISCLAIMER:
This tool is intended strictly for EDUCATIONAL PURPOSES.
It scans only PRIVATE LOCAL NETWORKS and should be used
ONLY on networks and systems you own or have permission to scan.

The author is not responsible for misuse.
"""

import socket
import threading
import ipaddress
import subprocess
import platform
from queue import Queue

# ================= CONFIG =================
PING_THREADS = 50     # Limited to avoid aggressive scanning
PORT_THREADS = 50
TIMEOUT = 1
# =========================================

# Common well-known services (educational mapping)
SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    8080: "HTTP-Alt"
}

# ========== LOCAL NETWORK DETECTION ==========
def detect_local_network():
    """
    Detects the private local network of the system.
    Uses a UDP socket without sending any packets.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Used only to determine local interface
        local_ip = s.getsockname()[0]
        s.close()

        network = ipaddress.ip_network(local_ip + "/24", strict=False)

        # Restrict scanning strictly to private networks
        if not network.is_private:
            return None

        return network
    except Exception:
        return None

# ========== PING FUNCTIONS ==========
def ping_host(ip):
    """
    Sends a single ICMP ping to check host availability.
    """
    param = "-n" if platform.system().lower() == "windows" else "-c"
    cmd = ["ping", param, "1", ip]

    return subprocess.call(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    ) == 0

def discover_hosts(network):
    """
    Performs a parallel ping sweep to discover live hosts.
    """
    print("\n🔍 Discovering active devices on the local network...\n")

    q = Queue()
    live_hosts = []
    lock = threading.Lock()

    for ip in network.hosts():
        q.put(str(ip))

    def worker():
        while not q.empty():
            ip = q.get()
            if ping_host(ip):
                with lock:
                    live_hosts.append(ip)
            q.task_done()

    for _ in range(PING_THREADS):
        threading.Thread(target=worker, daemon=True).start()

    q.join()
    return live_hosts

# ========== PORT SCANNING ==========
def scan_port(ip, port):
    """
    Attempts a TCP connection to determine if a port is open.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        if s.connect_ex((ip, port)) == 0:
            service = SERVICES.get(port, "Unknown")
            print(f"    [OPEN] {port:<5} {service}")
        s.close()
    except Exception:
        pass

def scan_host(ip, start_port, end_port):
    """
    Scans a single host for open TCP ports using threads.
    """
    print("\nScanning a discovered host")

    q = Queue()
    for port in range(start_port, end_port + 1):
        q.put(port)

    def worker():
        while not q.empty():
            scan_port(ip, q.get())
            q.task_done()

    for _ in range(PORT_THREADS):
        threading.Thread(target=worker, daemon=True).start()

    q.join()

# ========== MAIN ==========
def main():
    print("\nEthical Local Network Port Scanner")
    print("Educational use only — scans private LANs only\n")

    network = detect_local_network()
    if not network:
        print("Unable to detect a private local network.")
        return

    print("Private local network detected")

    try:
        start_port = int(input("\nEnter start port: "))
        end_port = int(input("Enter end port  : "))
    except ValueError:
        print("Ports must be valid numbers.")
        return

    if not (1 <= start_port <= end_port <= 65535):
        print("Invalid port range.")
        return

    try:
        hosts = discover_hosts(network)

        if not hosts:
            print("\nNo active devices found.")
            return

        print(f"\nActive devices found: {len(hosts)}")

        for host in hosts:
            scan_host(host, start_port, end_port)

    except KeyboardInterrupt:
        print("\n Scan interrupted by user.")

    print("\nScan completed safely within the local network.")

if __name__ == "__main__":
    main()
