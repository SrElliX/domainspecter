"""
Módulo Email Harvesting
Descobre e-mails corporativos expostos através de:
1. Registros WHOIS (reutiliza DNS/WHOIS)
2. Registros TXT do DNS (SPF revela serviços de e-mail)
3. Padrão de formato inferido (nome.sobrenome@domínio)
4. Busca em páginas públicas (contact/about)
"""

import socket
import urllib.request
import urllib.error
import ssl
import re

RESET  = "\033[0m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"

EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)

# Páginas que costumam ter e-mails expostos
CONTACT_PATHS = [
    "/contact", "/contact-us", "/about", "/about-us",
    "/team", "/people", "/staff", "/support",
    "/imprint", "/impressum", "/legal",
]


def fetch_page(url: str, timeout: int = 5) -> str:
    """Faz GET em uma URL e retorna o HTML como texto."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; OSINTRecon/1.0)"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read(50000).decode(errors="replace")
    except Exception:
        return ""


def extract_emails_from_text(text: str, domain: str) -> set[str]:
    """Extrai e-mails de um texto e filtra pelo domínio alvo."""
    found = EMAIL_REGEX.findall(text)
    # Filtra apenas e-mails do domínio alvo (evita ruído)
    return {e.lower() for e in found if domain in e.lower()}


def analyze_spf(domain: str, timeout: int = 5) -> list[str]:
    """
    Analisa o registro SPF (TXT) do DNS.
    SPF revela quais serviços enviam e-mail pelo domínio:
    include:mailchimp.net, include:sendgrid.net, etc.
    """
    from modules.dns_recon import query_dns
    txt_records = query_dns(domain, "TXT", timeout)
    spf_info = []

    for record in txt_records:
        if record.lower().startswith("v=spf1"):
            # Extrai os includes (provedores de e-mail)
            includes = re.findall(r"include:([^\s]+)", record)
            spf_info = includes
            print(f"  {BOLD}SPF:{RESET} {GRAY}{record[:80]}{RESET}")
            if includes:
                print(f"  Provedores de e-mail detectados:")
                for inc in includes:
                    print(f"    {CYAN}•{RESET} {inc}")
    return spf_info


def infer_email_format(domain: str) -> list[str]:
    """
    Gera exemplos dos formatos de e-mail corporativo mais comuns.
    Útil para saber o padrão antes de tentar descobrir e-mails reais.
    """
    formats = [
        f"nome.sobrenome@{domain}",
        f"n.sobrenome@{domain}",
        f"nome@{domain}",
        f"sobrenome@{domain}",
        f"nome_sobrenome@{domain}",
    ]
    # E-mails genéricos comuns
    generic = [
        f"contact@{domain}",
        f"info@{domain}",
        f"admin@{domain}",
        f"support@{domain}",
        f"hello@{domain}",
        f"team@{domain}",
        f"security@{domain}",
        f"abuse@{domain}",
    ]
    return formats, generic


def run_email_harvest(domain: str, timeout: int = 5) -> dict:
    results = {
        "found_emails":    [],
        "spf_providers":   [],
        "email_formats":   [],
        "generic_emails":  [],
        "pages_checked":   [],
    }

    # ── 1. SPF / DNS TXT ──────────────────────────────────
    print(f"  {GRAY}[1/3] Analisando registro SPF...{RESET}")
    results["spf_providers"] = analyze_spf(domain, timeout)

    # ── 2. Scraping de páginas de contato ─────────────────
    print(f"\n  {GRAY}[2/3] Buscando e-mails em páginas públicas...{RESET}")
    all_emails = set()

    for scheme in ("https", "http"):
        base = f"{scheme}://{domain}"
        # Testa homepage primeiro
        for path in [""] + CONTACT_PATHS:
            url = base + path
            html = fetch_page(url, timeout=timeout)
            if not html:
                continue

            found = extract_emails_from_text(html, domain)
            if found:
                all_emails |= found
                results["pages_checked"].append({"url": url, "emails_found": len(found)})
                print(f"    {GREEN}[+]{RESET} {url}")
                for email in found:
                    print(f"        {YELLOW}•{RESET} {email}")
            # Se já achamos e-mails na homepage HTTPS, para
            if path == "" and all_emails and scheme == "https":
                break

    if not all_emails:
        print(f"  {GRAY}Nenhum e-mail encontrado nas páginas públicas{RESET}")

    results["found_emails"] = sorted(all_emails)

    # ── 3. Formatos e e-mails genéricos inferidos ─────────
    print(f"\n  {GRAY}[3/3] Formatos de e-mail corporativo comuns:{RESET}")
    formats, generic = infer_email_format(domain)
    results["email_formats"]  = formats
    results["generic_emails"] = generic

    print(f"  {BOLD}Padrões prováveis:{RESET}")
    for fmt in formats:
        print(f"    {GRAY}•{RESET} {fmt}")

    print(f"\n  {BOLD}E-mails genéricos para verificar:{RESET}")
    for g in generic:
        print(f"    {CYAN}•{RESET} {g}")

    total = len(all_emails)
    if total:
        print(f"\n  {GREEN}[✓] {total} e-mail(s) reais encontrados{RESET}")

    return results
