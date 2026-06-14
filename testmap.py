import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
import json

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https",
    1433: "ms-sql", 3306: "mysql", 3389: "ms-wbt-server", 8080: "http-proxy"
}

def get_banner(sock, port):
    try:
        if port in [80, 443, 8080]:
            sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
        else:
            sock.sendall(b"\r\n")

        ready = sock.recv(128)
        if ready:
            banner = ready.decode('utf-8', errors='ignore').strip()
            return banner.replace('\r','').replace('\n', ' ')[:50]
    except:
        pass

    return COMMON_PORTS.get(port, "unknown")

def scan_port(target, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        result = sock.connect_ex((target, port))

        if result == 0:
            service = get_banner(sock, port)
            sock.close()
            return port, "open", service
        sock.close()
    except:
        pass
    return port, "closed", None

def parse_ports(port_arg):
    ports = []
    try:
        for part in port_arg.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return ports
    except ValueError:
        print("[-] Error: Format port bad, example: 22-80 or 22,80")
        sys.exit(1)

def print_help():
    print("""
Using: python3 testmap.py [target] [paramets]

PARAMETS
    -p <ports>
    -t <second>
    -w <flow> (:))
    -oJ <file>

example -> python3 testmap.py scanme.nmap.org -p 21-100 -w 150
    """)
    sys.exit(0)

def main():
    args = sys.argv[1:]
    if not args or "--hl" in args or "-h" in args:
        print_help()

    target_host = args[0]
    ports = list(range(1, 1001))
    timeout = 1.0
    threads = 100
    output_json = None

    try:
        if "-p" in args:
            ports = parse_ports(args[args.index("-p") + 1])
        if "-t" in args:
            timeout = float(args[args.index("-t") + 1])
        if "-w" in args:
            threads = int(args[args.index("-w") + 1])
        if "-oJ" in args:
            output_json = args[args.index("-oJ") + 1]
    except IndexError:
        print("[-] Error: Please paraments value ^-^")
        sys.exit(1)

    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"[-] Not root in namehost {target_host}")
        sys.exit(1)

    print(f"\nStarting TESTMAP (NN)")
    print(f"Report in scanning {target_host} ({target_ip})")
    print(f"Flow: {threads} | TimeOut: {timeout}с | Ports value: {len(ports)}\n")
    print(f"{'PORT':<10}{'STATUS':<10}{'SERVICE (BANNER)'}")
    print("-" * 50)

    start_time = time.time()
    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_port, target_ip, port, timeout) for port in ports]
        
        for future in futures:
            port, status, service = future.result()
            if status == "open":
                print(f"{str(port)+'/tcp':<10}{status:<10}{service}")
                results.append({"port": port, "status": status, "service": service})

    end_time = time.time()
    print("-" * 50)
    print(f"Scanning over: {len(results)} ports is open.")
    print(f"Time scanning: {end_time - start_time:.2f} second")

    if output_json:
        report = {
            "target": target_host,
            "IP": target_ip,
            "scan_time": round(end_time - start_time, 2),
            "open_ports": results
        }

        with open(output_json, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        print(f"[*] Result saving in file: {output_json}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Scanning over user.")
        sys.exit(0)
