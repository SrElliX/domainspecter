#!/usr/bin/env python3
"""
========================================
  OSINTRecon — OSINT Reconnaissance Tool
  Projeto educacional de cibersegurança
  Use apenas em alvos com permissão
========================================
"""

import argparse
import datetime
import json
import sys
import os

from modules.whois_lookup  import run_whois
from modules.dns_recon     import run_dns
from modules.subdomains    import run_subdomains
from modules.port_scan     import run_portscan
from modules.http_headers  import run_http_headers
from modules.email_harvest import run_email_harvest
from modules.report        import generate_report

# ──────────────────────────────────────────
# CORES ANSI
# ──────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
GRAY   = "\033[90m"
BLUE   = "\033[94m"
PURPLE = "\033[95m"


def banner():
    print(f"""
{PURPLE}{BOLD}
██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗
██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║
██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║
██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║
██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
        DomainSpecter — OSINT Recon Tool
             by SrElliX
{RESET}""")


def print_section(title, color=CYAN):
    width = 52
    print(f"\n{color}{BOLD}{'─'*width}")
    print(f"  {title}")
    print(f"{'─'*width}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="DomainSpecter — OSINT Recon Tool by SrElliX",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  python3 recon.py -d example.com
  python3 recon.py -d example.com --all
  python3 recon.py -d example.com --whois --dns --subdomains
  python3 recon.py -d example.com --ports --headers
  python3 recon.py -d example.com --all --output report.json
        """,
    )

    parser.add_argument("-d", "--domain",     required=True, help="Domínio alvo (ex: example.com)")
    parser.add_argument("--all",              action="store_true", help="Executar todos os módulos")
    parser.add_argument("--whois",            action="store_true", help="WHOIS lookup")
    parser.add_argument("--dns",              action="store_true", help="Enumeração DNS")
    parser.add_argument("--subdomains",       action="store_true", help="Enumeração de subdomínios")
    parser.add_argument("--ports",            action="store_true", help="Port scan (top 100 portas)")
    parser.add_argument("--headers",          action="store_true", help="HTTP headers")
    parser.add_argument("--emails",           action="store_true", help="Coleta de e-mails expostos")
    parser.add_argument("--output", "-o",     help="Salvar relatório em arquivo JSON/TXT")
    parser.add_argument("--timeout",          type=int, default=5, help="Timeout de conexão em segundos (padrão: 5)")

    args = parser.parse_args()

    # Se --all, ativa tudo
    if args.all:
        args.whois = args.dns = args.subdomains = args.ports = args.headers = args.emails = True

    # Se nenhum módulo foi selecionado, ativa os passivos por padrão
    if not any([args.whois, args.dns, args.subdomains, args.ports, args.headers, args.emails]):
        print(f"{YELLOW}[!] Nenhum módulo selecionado. Executando módulos passivos (--whois --dns --subdomains).{RESET}")
        args.whois = args.dns = args.subdomains = True

    banner()

    domain    = args.domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"{BOLD}Alvo:{RESET}     {BLUE}{domain}{RESET}")
    print(f"{BOLD}Início:{RESET}   {timestamp}")
    print(f"{BOLD}Timeout:{RESET}  {args.timeout}s")

    # Estrutura que vai acumular todos os resultados
    results = {
        "target":    domain,
        "timestamp": timestamp,
        "modules":   {}
    }

    # ── WHOIS ──────────────────────────────
    if args.whois:
        print_section("WHOIS Lookup", PURPLE)
        data = run_whois(domain)
        results["modules"]["whois"] = data

    # ── DNS ────────────────────────────────
    if args.dns:
        print_section("DNS Reconnaissance", PURPLE)
        data = run_dns(domain)
        results["modules"]["dns"] = data

    # ── SUBDOMÍNIOS ────────────────────────
    if args.subdomains:
        print_section("Subdomain Enumeration", PURPLE)
        data = run_subdomains(domain, timeout=args.timeout)
        results["modules"]["subdomains"] = data

    # ── PORT SCAN ──────────────────────────
    if args.ports:
        print_section("Port Scan", CYAN)
        data = run_portscan(domain, timeout=args.timeout)
        results["modules"]["ports"] = data

    # ── HTTP HEADERS ───────────────────────
    if args.headers:
        print_section("HTTP Headers Analysis", CYAN)
        data = run_http_headers(domain, timeout=args.timeout)
        results["modules"]["http_headers"] = data

    # ── EMAIL HARVEST ──────────────────────
    if args.emails:
        print_section("Email Harvesting", CYAN)
        data = run_email_harvest(domain, timeout=args.timeout)
        results["modules"]["emails"] = data

    # ── RELATÓRIO ──────────────────────────
    print_section("Relatório Final", YELLOW)
    generate_report(results)

    if args.output:
        output_path = args.output
        if output_path.endswith(".json"):
            with open(output_path, "w") as f:
                json.dump(results, f, indent=2, default=str)
        else:
            with open(output_path, "w") as f:
                generate_report(results, file=f)
        print(f"\n{GREEN}[✓] Relatório salvo em: {output_path}{RESET}")

    print(f"\n{GRAY}Reconhecimento concluído às {datetime.datetime.now().strftime('%H:%M:%S')}{RESET}\n")


if __name__ == "__main__":
    main()