import socket
import threading
import ipaddress
import subprocess
import platform
import json
import argparse
import sys
from queue import Queue

# ================= CONFIG =================
PING_THREADS = 100
PORT_THREADS = 100
HOST_THREADS = 10
TIMEOUT = 0.5
# =========================================

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

# ========== AUTO-DETECT LOCAL NETWORK ==========
def detect_local_network():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # no packets sent
        local_ip = s.getsockname()[0]
        s.close()

        network = ipaddress.ip_network(local_ip + "/24", strict=False)

        if not network.is_private:
            return None, None

        return local_ip, network
    except:
        return None, None

# ========== PING ==========================
def ping_host(ip):
    is_windows = platform.system().lower() == "windows"
    param = "-n" if is_windows else "-c"
    # -w 500 on Windows is 500ms timeout. -W 1 on Linux is 1s timeout.
    timeout_param = ["-w", "500"] if is_windows else ["-W", "1"]
    cmd = ["ping", param, "1"] + timeout_param + [ip]

    return subprocess.call(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    ) == 0

def discover_hosts(network, verbose=True):
    if verbose:
        print(f"🔍 Scanning {network} for live hosts...")

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
                    if verbose:
                        print(f"  [LIVE] {ip}")
                    live_hosts.append(ip)
            q.task_done()

    for _ in range(PING_THREADS):
        t = threading.Thread(target=worker, daemon=True)
        t.start()

    q.join()
    return live_hosts

# ========== PORT SCANNER ==================
def scan_port(ip, port, results, lock, verbose=True):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        if s.connect_ex((ip, port)) == 0:
            service = SERVICES.get(port, "Unknown")
            with lock:
                results.append({"port": port, "service": service})
                if verbose:
                    print(f"    [{ip}] OPEN: {port} ({service})")
        s.close()
    except:
        pass

def scan_host(ip, start_port, end_port, verbose=True):
    results = []
    lock = threading.Lock()
    q = Queue()
    for port in range(start_port, end_port + 1):
        q.put(port)

    def worker():
        while not q.empty():
            scan_port(ip, q.get(), results, lock, verbose)
            q.task_done()

    threads = []
    num_threads = min(PORT_THREADS, (end_port - start_port) + 1)
    for _ in range(num_threads):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    q.join()
    return results

# ========== MAIN ==========================
def main():
    parser = argparse.ArgumentParser(description="Ethical Local Network Port Scanner")
    parser.add_argument("--start", type=int, default=1, help="Start port")
    parser.add_argument("--end", type=int, default=1024, help="End port")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    local_ip, network = detect_local_network()

    if not network:
        if args.json:
            print(json.dumps({"error": "Could not detect a private local network."}))
        else:
            print("❌ Could not detect a private local network.")
        return

    if not args.json:
        print("\n🔐 Ethical Local Network Port Scanner")
        print(f"🖥️  Local IP    : {local_ip}")
        print(f"🌐 LAN Network : {network}")
        print(f"⏱️  Port Timeout: {TIMEOUT}s\n")

    try:
        hosts = discover_hosts(network, verbose=not args.json)

        if not hosts:
            if args.json:
                print(json.dumps({"hosts": []}))
            else:
                print("\n❌ No active devices found.")
            return

        if not args.json:
            print(f"\n✅ Found {len(hosts)} hosts. Scanning ports {args.start}-{args.end}...")

        final_results = []
        results_lock = threading.Lock()
        host_queue = Queue()
        for host in hosts:
            host_queue.put(host)

        def host_worker():
            while not host_queue.empty():
                host = host_queue.get()
                port_results = scan_host(host, args.start, args.end, verbose=not args.json)
                with results_lock:
                    final_results.append({"ip": host, "open_ports": port_results})
                host_queue.task_done()

        for _ in range(min(HOST_THREADS, len(hosts))):
            threading.Thread(target=host_worker, daemon=True).start()

        host_queue.join()

        if args.json:
            print(json.dumps({
                "local_ip": local_ip,
                "network": str(network),
                "hosts": final_results
            }, indent=2))
        else:
            print("\n✅ Scan completed.")

    except KeyboardInterrupt:
        if not args.json:
            print("\n⚠️ Scan stopped by user.")
        sys.exit(1)

if __name__ == "__main__":
    main()
