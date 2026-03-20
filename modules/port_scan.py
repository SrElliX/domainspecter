"""
Módulo Port Scanner
Scan das portas mais comuns com detecção de banner.
Versão simplificada do projeto NetSniffer — reutiliza os conceitos de socket.
"""

import socket
import concurrent.futures

RESET  = "\033[0m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"

# Top portas mais comuns em servidores web e aplicações
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 465, 587, 993, 995, 1433, 1521,
    2082, 2083, 2086, 2087, 3000, 3306, 3389, 4443,
    5432, 5900, 6379, 8000, 8080, 8081, 8443, 8888,
    9200, 9300, 27017,
]

# Serviços conhecidos por porta
SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP/TLS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2082: "cPanel",
    2083: "cPanel-SSL", 2086: "WHM", 2087: "WHM-SSL",
    3000: "Dev/Grafana", 3306: "MySQL", 3389: "RDP",
    4443: "Alt-HTTPS", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8000: "Dev", 8080: "HTTP-alt",
    8081: "HTTP-alt2", 8443: "HTTPS-alt", 8888: "Jupyter",
    9200: "Elasticsearch", 9300: "Elasticsearch-cluster",
    27017: "MongoDB",
}

# Probes para capturar banner por protocolo
BANNER_PROBES = {
    80:   b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    443:  b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    21:   b"",     # FTP envia banner automaticamente
    22:   b"",     # SSH também
    25:   b"",     # SMTP também
}


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str | None:
    """Tenta capturar o banner de um serviço após conectar."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            probe = BANNER_PROBES.get(port, b"")
            if probe:
                sock.sendall(probe.replace(b"{host}", host.encode()))
            sock.settimeout(1.5)
            banner = sock.recv(512).decode(errors="replace").strip()
            # Pega só a primeira linha do banner
            first_line = banner.split("\n")[0][:100]
            return first_line if first_line else None
    except Exception:
        return None


def scan_port(host: str, port: int, timeout: float) -> dict | None:
    """
    Tenta conectar na porta. Retorna dict com info se aberta, None se fechada.
    TCP connect scan — método mais confiável sem raw socket.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            service = SERVICES.get(port, "unknown")
            banner  = grab_banner(host, port, timeout=timeout)
            return {
                "port":    port,
                "service": service,
                "banner":  banner,
            }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def run_portscan(domain: str, timeout: int = 3) -> dict:
    # Resolve o IP primeiro
    try:
        ip = socket.gethostbyname(domain)
        print(f"  IP resolvido: {CYAN}{ip}{RESET}")
    except socket.gaierror as e:
        print(f"  {RED}[!] Não foi possível resolver {domain}: {e}{RESET}")
        return {"error": str(e), "open_ports": []}

    print(f"  Escaneando {len(TOP_PORTS)} portas com {min(50, len(TOP_PORTS))} threads...\n")

    open_ports = []

    # Scan paralelo — muito mais rápido
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in TOP_PORTS
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    # Ordena por número de porta
    open_ports.sort(key=lambda x: x["port"])

    if open_ports:
        print(f"  {GREEN}[+] {len(open_ports)} porta(s) abertas:{RESET}\n")
        print(f"  {'PORTA':<8} {'SERVIÇO':<18} BANNER")
        print(f"  {'─'*60}")
        for p in open_ports:
            banner_str = f"{GRAY}{p['banner'][:60]}{RESET}" if p["banner"] else ""
            print(f"  {GREEN}{p['port']:<8}{RESET} {p['service']:<18} {banner_str}")
    else:
        print(f"  {GRAY}Nenhuma porta aberta encontrada nas portas testadas.{RESET}")

    return {"target_ip": ip, "open_ports": open_ports, "scanned": len(TOP_PORTS)}
