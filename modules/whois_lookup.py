"""
Módulo WHOIS
Consulta informações de registro de domínio via socket direto ao servidor WHOIS.
Sem dependências externas — implementado manualmente para fins educacionais.
"""

import socket
import re

RESET  = "\033[0m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"

# Servidores WHOIS por TLD
WHOIS_SERVERS = {
    "com":  "whois.verisign-grs.com",
    "net":  "whois.verisign-grs.com",
    "org":  "whois.pir.org",
    "io":   "whois.iana.org",
    "br":   "whois.registro.br",
    "uk":   "whois.nic.uk",
    "de":   "whois.denic.de",
    "fr":   "whois.afnic.fr",
    "gov":  "whois.dotgov.gov",
    "edu":  "whois.educause.edu",
}
DEFAULT_SERVER = "whois.iana.org"


def query_whois(domain: str, server: str, timeout: int = 5) -> str:
    """Faz query raw ao servidor WHOIS via socket TCP porta 43."""
    try:
        with socket.create_connection((server, 43), timeout=timeout) as sock:
            # Protocolo WHOIS: envia domínio + \r\n, recebe resposta em texto
            sock.sendall(f"{domain}\r\n".encode())
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response.decode(errors="replace")
    except Exception as e:
        return f"ERRO: {e}"


def parse_whois(raw: str) -> dict:
    """Extrai campos relevantes da resposta WHOIS com regex."""
    fields = {
        "registrar":      None,
        "creation_date":  None,
        "expiry_date":    None,
        "updated_date":   None,
        "name_servers":   [],
        "status":         [],
        "registrant_org": None,
        "registrant_country": None,
        "emails":         [],
    }

    patterns = {
        "registrar":          r"(?:Registrar|registrar):\s*(.+)",
        "creation_date":      r"(?:Creation Date|Created|creation date):\s*(.+)",
        "expiry_date":        r"(?:Expir\w+ Date|expir\w+ date|Registry Expiry Date):\s*(.+)",
        "updated_date":       r"(?:Updated Date|Last Modified|last-modified):\s*(.+)",
        "registrant_org":     r"(?:Registrant Organization|org):\s*(.+)",
        "registrant_country": r"(?:Registrant Country|country):\s*(.+)",
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, raw, re.IGNORECASE)
        if match:
            fields[key] = match.group(1).strip()

    # Name servers (podem aparecer múltiplos)
    ns_matches = re.findall(r"(?:Name Server|nserver):\s*(.+)", raw, re.IGNORECASE)
    fields["name_servers"] = list({ns.strip().lower() for ns in ns_matches})

    # Status
    status_matches = re.findall(r"(?:Domain Status|status):\s*(.+)", raw, re.IGNORECASE)
    fields["status"] = list({s.strip() for s in status_matches})[:3]

    # E-mails expostos no WHOIS
    email_matches = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", raw)
    fields["emails"] = list(set(email_matches))

    return fields


def run_whois(domain: str) -> dict:
    tld = domain.split(".")[-1].lower()
    server = WHOIS_SERVERS.get(tld, DEFAULT_SERVER)

    print(f"  Servidor WHOIS: {GRAY}{server}{RESET}")

    raw = query_whois(domain, server)

    if raw.startswith("ERRO"):
        print(f"  {RED}{raw}{RESET}")
        return {"error": raw, "raw": ""}

    parsed = parse_whois(raw)

    # Exibe resultados formatados
    fields_display = {
        "Registrar":    parsed["registrar"],
        "Criado em":    parsed["creation_date"],
        "Expira em":    parsed["expiry_date"],
        "Atualizado":   parsed["updated_date"],
        "Organização":  parsed["registrant_org"],
        "País":         parsed["registrant_country"],
    }

    for label, value in fields_display.items():
        if value:
            print(f"  {BOLD}{label:<14}{RESET} {value}")

    if parsed["name_servers"]:
        print(f"\n  {BOLD}Name Servers:{RESET}")
        for ns in parsed["name_servers"]:
            print(f"    {GREEN}•{RESET} {ns}")

    if parsed["emails"]:
        print(f"\n  {BOLD}E-mails encontrados:{RESET}")
        for email in parsed["emails"]:
            print(f"    {YELLOW}•{RESET} {email}")

    if parsed["status"]:
        print(f"\n  {BOLD}Status:{RESET}")
        for s in parsed["status"]:
            print(f"    {GRAY}•{RESET} {s}")

    parsed["raw_excerpt"] = raw[:500]
    return parsed
