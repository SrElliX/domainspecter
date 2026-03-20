"""
Módulo Report
Gera relatório final consolidado de todos os módulos.
"""

import sys

RESET  = "\033[0m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
PURPLE = "\033[95m"


def generate_report(results: dict, file=None) -> None:
    """
    Gera o sumário final no terminal (ou em arquivo).
    Consolida os achados mais importantes de cada módulo.
    """
    out = file or sys.stdout

    def w(text=""):
        print(text, file=out)

    if file:
        # Versão sem cores para arquivo
        w("=" * 60)
        w(f"  OSINT RECON REPORT")
        w(f"  Alvo:     {results['target']}")
        w(f"  Data:     {results['timestamp']}")
        w("=" * 60)
    else:
        print(f"\n{PURPLE}{BOLD}{'═'*52}")
        print(f"  SUMÁRIO DO RECONHECIMENTO")
        print(f"  Alvo: {CYAN}{results['target']}{PURPLE}")
        print(f"{'═'*52}{RESET}")

    modules = results.get("modules", {})

    # ── WHOIS ──────────────────────────────────────────────
    if "whois" in modules:
        w_data = modules["whois"]
        if file:
            w("\n[WHOIS]")
            for field in ("registrar", "creation_date", "expiry_date", "registrant_country"):
                if w_data.get(field):
                    w(f"  {field}: {w_data[field]}")
        else:
            print(f"\n{BOLD}WHOIS{RESET}")
            for label, field in [("Registrar", "registrar"), ("Criado", "creation_date"),
                                  ("Expira", "expiry_date"), ("País", "registrant_country")]:
                if w_data.get(field):
                    print(f"  {GRAY}{label}:{RESET} {w_data[field]}")

    # ── DNS ────────────────────────────────────────────────
    if "dns" in modules:
        d_data = modules["dns"]
        if file:
            w("\n[DNS]")
            for rtype in ("A", "MX", "NS"):
                records = d_data.get(rtype, [])
                if records:
                    w(f"  {rtype}: {', '.join(records[:5])}")
        else:
            print(f"\n{BOLD}DNS{RESET}")
            for rtype in ("A", "AAAA", "MX", "NS"):
                records = d_data.get(rtype, [])
                if records:
                    print(f"  {GRAY}{rtype}:{RESET} {', '.join(records[:4])}")

    # ── SUBDOMÍNIOS ────────────────────────────────────────
    if "subdomains" in modules:
        s_data = modules["subdomains"]
        total  = s_data.get("total_unique", 0)
        if file:
            w(f"\n[SUBDOMAINS] Total: {total}")
            for item in s_data.get("bruteforce", [])[:10]:
                w(f"  {item['subdomain']} → {item['ip']}")
        else:
            print(f"\n{BOLD}Subdomínios{RESET}  ({total} únicos)")
            for item in s_data.get("bruteforce", [])[:8]:
                print(f"  {GREEN}•{RESET} {item['subdomain']:<40} {GRAY}{item['ip']}{RESET}")
            crt_count = len(s_data.get("crtsh", []))
            if crt_count:
                print(f"  {GRAY}+ {crt_count} via crt.sh (ver relatório JSON){RESET}")

    # ── PORTAS ─────────────────────────────────────────────
    if "ports" in modules:
        p_data  = modules["ports"]
        ports   = p_data.get("open_ports", [])
        if file:
            w(f"\n[PORTS] {len(ports)} aberta(s)")
            for p in ports:
                w(f"  {p['port']}/{p['service']}")
        else:
            print(f"\n{BOLD}Portas abertas{RESET}  ({len(ports)})")
            for p in ports:
                banner = f"  {GRAY}{p['banner'][:50]}{RESET}" if p.get("banner") else ""
                print(f"  {GREEN}{p['port']:<6}{RESET} {p['service']:<16}{banner}")

    # ── HTTP HEADERS ───────────────────────────────────────
    if "http_headers" in modules:
        h_data = modules["http_headers"]
        scheme = "https" if "https" in h_data else "http"
        if scheme in h_data:
            headers = h_data[scheme].get("headers", {})
            if file:
                w(f"\n[HTTP HEADERS]")
                for tech_h in ("Server", "X-Powered-By", "Via"):
                    val = next((v for k, v in headers.items() if k.lower() == tech_h.lower()), None)
                    if val:
                        w(f"  {tech_h}: {val}")
            else:
                print(f"\n{BOLD}HTTP Headers{RESET}")
                for tech_h in ("Server", "X-Powered-By", "X-Generator", "Via", "CF-Ray"):
                    val = next((v for k, v in headers.items() if k.lower() == tech_h.lower()), None)
                    if val:
                        print(f"  {YELLOW}•{RESET} {tech_h}: {val}")

    # ── E-MAILS ────────────────────────────────────────────
    if "emails" in modules:
        e_data = modules["emails"]
        emails = e_data.get("found_emails", [])
        spf    = e_data.get("spf_providers", [])
        if file:
            w(f"\n[EMAILS] {len(emails)} encontrado(s)")
            for e in emails:
                w(f"  {e}")
            if spf:
                w(f"  SPF providers: {', '.join(spf)}")
        else:
            print(f"\n{BOLD}E-mails{RESET}")
            if emails:
                for e in emails:
                    print(f"  {YELLOW}•{RESET} {e}")
            if spf:
                print(f"  {GRAY}SPF providers: {', '.join(spf)}{RESET}")

    if file:
        w("\n" + "=" * 60)
        w("  Use apenas em alvos com autorização explícita.")
        w("=" * 60)
    else:
        print(f"\n{GRAY}{'─'*52}")
        print(f"  Use apenas em alvos com autorização explícita.{RESET}\n")
