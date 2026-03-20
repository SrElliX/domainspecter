"""
Módulo Subdomain Enumeration
Duas estratégias:
1. Certificate Transparency Logs (passivo) — crt.sh API
2. Wordlist bruteforce via DNS (ativo)
"""

import socket
import urllib.request
import urllib.error
import json
import concurrent.futures

RESET  = "\033[0m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"

# Wordlist de subdomínios mais comuns para bruteforce
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "admin", "panel", "dashboard", "portal", "api", "api2",
    "dev", "staging", "test", "beta", "demo", "sandbox",
    "blog", "shop", "store", "app", "mobile", "m",
    "vpn", "remote", "ssh", "rdp", "citrix",
    "ns1", "ns2", "dns", "dns1", "dns2",
    "cdn", "static", "assets", "img", "media",
    "git", "gitlab", "github", "jenkins", "ci", "jira",
    "monitor", "grafana", "kibana", "elastic",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "backup", "files", "upload", "download",
    "auth", "sso", "login", "accounts", "oauth",
    "status", "health", "metrics", "logs",
    "support", "help", "docs", "wiki",
    "mx1", "mx2", "relay", "exchange",
]


def fetch_crtsh(domain: str, timeout: int = 8) -> list[str]:
    """
    Consulta a API do crt.sh (Certificate Transparency Log).
    Cada certificado SSL emitido fica registrado publicamente.
    Fonte totalmente passiva — não toca no alvo.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains = set()

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "OSINTRecon/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())

        for entry in data:
            name = entry.get("name_value", "")
            # Pode conter múltiplos domínios separados por \n
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                # Remove wildcards e filtra pelo domínio correto
                if sub.startswith("*."):
                    sub = sub[2:]
                if sub.endswith(f".{domain}") or sub == domain:
                    subdomains.add(sub)

    except urllib.error.URLError:
        print(f"  {YELLOW}[!] crt.sh indisponível — verifique conexão com internet{RESET}")
    except Exception as e:
        print(f"  {YELLOW}[!] Erro ao consultar crt.sh: {e}{RESET}")

    return sorted(subdomains)


def resolve_subdomain(subdomain: str, timeout: int = 2) -> tuple[str, str | None]:
    """Tenta resolver um subdomínio para IP. Retorna (subdominio, ip_ou_None)."""
    try:
        ip = socket.gethostbyname(subdomain)
        return subdomain, ip
    except socket.gaierror:
        return subdomain, None


def bruteforce_subdomains(domain: str, timeout: int = 3) -> list[dict]:
    """
    Testa subdomínios comuns tentando resolver no DNS.
    Usa ThreadPoolExecutor para fazer múltiplas queries em paralelo.
    """
    candidates = [f"{sub}.{domain}" for sub in COMMON_SUBDOMAINS]
    found = []

    # Resolve em paralelo — muito mais rápido que sequencial
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(resolve_subdomain, sub, timeout): sub for sub in candidates}
        for future in concurrent.futures.as_completed(futures):
            sub, ip = future.result()
            if ip:
                found.append({"subdomain": sub, "ip": ip})

    return sorted(found, key=lambda x: x["subdomain"])


def run_subdomains(domain: str, timeout: int = 5) -> dict:
    results = {"crtsh": [], "bruteforce": []}

    # ── Certificate Transparency (passivo) ────────────────
    print(f"  {GRAY}[1/2] Consultando Certificate Transparency Logs (crt.sh)...{RESET}")
    crt_subs = fetch_crtsh(domain, timeout=timeout + 3)
    results["crtsh"] = crt_subs

    if crt_subs:
        print(f"  {GREEN}[+] {len(crt_subs)} subdomínio(s) encontrado(s) via crt.sh:{RESET}")
        for sub in crt_subs[:20]:   # limita exibição a 20
            print(f"    {GREEN}•{RESET} {sub}")
        if len(crt_subs) > 20:
            print(f"    {GRAY}... e mais {len(crt_subs) - 20} no relatório JSON{RESET}")
    else:
        print(f"  {GRAY}Nenhum resultado no crt.sh{RESET}")

    # ── Bruteforce por wordlist (ativo) ───────────────────
    print(f"\n  {GRAY}[2/2] Bruteforce com wordlist ({len(COMMON_SUBDOMAINS)} candidatos)...{RESET}")
    bf_found = bruteforce_subdomains(domain, timeout=2)
    results["bruteforce"] = bf_found

    if bf_found:
        print(f"  {YELLOW}[+] {len(bf_found)} subdomínio(s) resolvido(s):{RESET}")
        for item in bf_found:
            print(f"    {YELLOW}•{RESET} {item['subdomain']:<40} {GRAY}{item['ip']}{RESET}")
    else:
        print(f"  {GRAY}Nenhum subdomínio encontrado por bruteforce{RESET}")

    # Total único
    all_subs = set(crt_subs) | {item["subdomain"] for item in bf_found}
    print(f"\n  {BOLD}Total de subdomínios únicos: {len(all_subs)}{RESET}")
    results["total_unique"] = len(all_subs)

    return results
