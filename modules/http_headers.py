"""
Módulo HTTP Headers Analysis
Analisa headers de resposta HTTP/HTTPS para identificar:
- Tecnologias do servidor (Server, X-Powered-By)
- Configurações de segurança (ou ausência delas)
- Frameworks e CDNs
"""

import urllib.request
import urllib.error
import ssl

RESET  = "\033[0m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"

# Headers de segurança que deveriam estar presentes
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS — força HTTPS",
    "Content-Security-Policy":   "CSP — previne XSS",
    "X-Frame-Options":           "previne clickjacking",
    "X-Content-Type-Options":    "previne MIME sniffing",
    "Referrer-Policy":           "controla informação de referência",
    "Permissions-Policy":        "controla APIs do browser",
    "X-XSS-Protection":          "proteção XSS legada",
}

# Headers que revelam tecnologias (interessantes para OSINT)
TECH_HEADERS = [
    "Server", "X-Powered-By", "X-Generator", "X-Drupal-Cache",
    "X-WordPress", "X-AspNet-Version", "X-AspNetMvc-Version",
    "Via", "X-Cache", "CF-Ray", "X-Served-By",
    "X-Varnish", "X-Backend-Server", "X-Application-Context",
]


def fetch_headers(url: str, timeout: int = 5) -> dict | None:
    """Faz requisição HEAD e retorna os headers de resposta."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE   # ignora cert inválido (útil em lab)

    try:
        req = urllib.request.Request(
            url,
            method="HEAD",
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; OSINTRecon/1.0)",
                "Accept":     "*/*",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {
                "status":       resp.status,
                "url":          resp.url,
                "headers":      dict(resp.headers),
            }
    except urllib.error.HTTPError as e:
        # Mesmo com erro HTTP, pode ter headers úteis
        return {
            "status":   e.code,
            "url":      url,
            "headers":  dict(e.headers) if e.headers else {},
        }
    except Exception as e:
        return None


def run_http_headers(domain: str, timeout: int = 5) -> dict:
    results = {}

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        print(f"  Requisição HEAD → {CYAN}{url}{RESET}")
        data = fetch_headers(url, timeout=timeout)

        if data:
            results[scheme] = data
            headers = data["headers"]

            print(f"  Status: {GREEN if data['status'] < 400 else RED}{data['status']}{RESET}")

            # Headers que revelam tecnologia
            print(f"\n  {BOLD}Tecnologias identificadas:{RESET}")
            found_tech = False
            for h in TECH_HEADERS:
                # Headers são case-insensitive
                value = next((v for k, v in headers.items() if k.lower() == h.lower()), None)
                if value:
                    print(f"    {YELLOW}•{RESET} {h}: {value}")
                    found_tech = True
            if not found_tech:
                print(f"    {GRAY}Nenhum header de tecnologia encontrado{RESET}")

            # Análise de segurança
            print(f"\n  {BOLD}Headers de segurança:{RESET}")
            for header, description in SECURITY_HEADERS.items():
                value = next((v for k, v in headers.items() if k.lower() == header.lower()), None)
                if value:
                    print(f"    {GREEN}[OK]{RESET} {header}")
                else:
                    print(f"    {RED}[--]{RESET} {header:<40} {GRAY}({description}){RESET}")

            # Cookies — verificar flags de segurança
            cookies = [v for k, v in headers.items() if k.lower() == "set-cookie"]
            if cookies:
                print(f"\n  {BOLD}Cookies ({len(cookies)}):{RESET}")
                for cookie in cookies[:5]:
                    flags = []
                    if "httponly" in cookie.lower():  flags.append(f"{GREEN}HttpOnly{RESET}")
                    else:                              flags.append(f"{RED}sem HttpOnly{RESET}")
                    if "secure" in cookie.lower():    flags.append(f"{GREEN}Secure{RESET}")
                    else:                             flags.append(f"{RED}sem Secure{RESET}")
                    if "samesite" in cookie.lower():  flags.append(f"{GREEN}SameSite{RESET}")
                    cookie_name = cookie.split("=")[0]
                    print(f"    • {cookie_name[:30]:<30}  {' | '.join(flags)}")

            # Se HTTPS, para — não precisa testar HTTP
            if scheme == "https" and data["status"] < 500:
                break
        else:
            print(f"  {GRAY}Sem resposta em {url}{RESET}")

    return results
