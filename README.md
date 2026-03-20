<div align="center">

```
██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗
██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║
██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║
██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║
██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
        DomainSpecter — OSINT Recon Tool
             by SrElliX
```

**DomainSpecter** — ferramenta de reconhecimento OSINT modular em Python puro

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=flat-square&logo=linux)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Educational-purple?style=flat-square)
![Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen?style=flat-square)
![Lines](https://img.shields.io/badge/Lines_of_code-1208-informational?style=flat-square)

> *"Um espectro que observa tudo, sem deixar rastros."*

</div>

---

## Índice

- [Sobre o projeto](#sobre-o-projeto)
- [Como funciona](#como-funciona)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Como usar](#como-usar)
- [Módulos](#módulos)
  - [WHOIS Lookup](#whois-lookup)
  - [DNS Recon](#dns-recon)
  - [Subdomain Enumeration](#subdomain-enumeration)
  - [Port Scanner](#port-scanner)
  - [HTTP Headers Analysis](#http-headers-analysis)
  - [Email Harvesting](#email-harvesting)
- [Exemplos de saída](#exemplos-de-saída)
- [Arquitetura do código](#arquitetura-do-código)
- [Flags e argumentos](#flags-e-argumentos)
- [Aviso legal](#aviso-legal)
- [Próximos passos](#próximos-passos)
- [Referências técnicas](#referências-técnicas)

---

## Sobre o projeto

**DomainSpecter** é uma ferramenta de reconhecimento OSINT *(Open Source Intelligence)* desenvolvida em **Python puro**, sem nenhuma dependência externa. Ela automatiza a fase de reconhecimento de um pentest, coletando informações públicas sobre um alvo (domínio ou IP) de forma passiva e ativa.

O projeto foi construído do zero com fins educacionais — cada módulo implementa manualmente os protocolos envolvidos (DNS via UDP raw, WHOIS via TCP raw, port scan via TCP connect), sem uso de bibliotecas como `dnspython`, `python-whois` ou `nmap`. O objetivo é aprender como as ferramentas funcionam por dentro.

**O que o DomainSpecter coleta:**

- Informações de registro do domínio via WHOIS (proprietário, datas, nameservers)
- Registros DNS completos (A, AAAA, MX, NS, TXT, CNAME)
- Subdomínios via Certificate Transparency Logs e bruteforce paralelo
- Portas abertas com identificação de serviço e captura de banner
- Headers HTTP com análise de configurações de segurança
- E-mails expostos via SPF, scraping de páginas públicas e padrões corporativos
- Relatório consolidado em texto e JSON

---

## Como funciona

```
                      ┌─────────────────────┐
                      │   Alvo (domínio)    │
                      └──────────┬──────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
              ▼                  ▼                  ▼
    ┌─────────────────┐ ┌──────────────┐ ┌──────────────────┐
    │     WHOIS       │ │  DNS RECON   │ │  SUBDOMÍNIOS     │
    │                 │ │              │ │                  │
    │  TCP porta 43   │ │  UDP porta   │ │  crt.sh API +    │
    │  raw socket     │ │  53 raw      │ │  bruteforce DNS  │
    │  parsing regex  │ │  A MX NS TXT │ │  paralelo        │
    └────────┬────────┘ └──────┬───────┘ └────────┬─────────┘
             │                 │                  │
             └─────────────────┼──────────────────┘
                               │   PASSIVO
          ═══════════════════════════════════════════
                               │   ATIVO
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐
    │  PORT SCAN   │  │ HTTP HEADERS │  │ EMAIL HARVEST    │
    │              │  │              │  │                  │
    │  TCP connect │  │  HEAD req.   │  │  SPF + scraping  │
    │  banner grab │  │  análise CSP │  │  padrões corp.   │
    │  50 threads  │  │  fingerprint │  │  regex harvest   │
    └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘
           │                 │                   │
           └─────────────────┼───────────────────┘
                             │
                             ▼
                 ┌───────────────────────┐
                 │    RELATÓRIO FINAL    │
                 │   terminal + JSON     │
                 └───────────────────────┘
```

### Reconhecimento passivo vs ativo

| Tipo | Módulos | O que significa |
|------|---------|-----------------|
| **Passivo** | WHOIS, DNS, Subdomains (crt.sh) | Coleta dados de fontes públicas sem tocar no alvo |
| **Ativo** | Port Scan, HTTP Headers, Email Scraping | Faz requisições diretas ao alvo |

Em pentest real, o reconhecimento passivo sempre precede o ativo — primeiro você coleta o máximo possível sem alertar o alvo, depois você toca nele com cautela.

---

## Estrutura do projeto

```
domainspecter/
│
├── specter.py               ← ponto de entrada principal
│
└── modules/
    ├── __init__.py
    ├── whois_lookup.py      ← query WHOIS via TCP raw (porta 43)
    ├── dns_recon.py         ← query DNS via UDP raw (porta 53)
    ├── subdomains.py        ← crt.sh + bruteforce paralelo
    ├── port_scan.py         ← TCP connect scan + banner grabbing
    ├── http_headers.py      ← análise de segurança de headers HTTP
    ├── email_harvest.py     ← SPF + web scraping + padrões
    └── report.py            ← geração de relatório consolidado
```

**Linhas de código por módulo:**

| Arquivo | Linhas | Responsabilidade |
|---------|--------|-----------------|
| `specter.py` | 165 | Orquestração, CLI, fluxo principal |
| `dns_recon.py` | 198 | Parser DNS manual com `struct` |
| `email_harvest.py` | 169 | SPF, scraping, padrões corporativos |
| `report.py` | 148 | Formatação e exportação do relatório |
| `whois_lookup.py` | 137 | Socket TCP porta 43, regex de parsing |
| `subdomains.py` | 136 | crt.sh API + `ThreadPoolExecutor` |
| `http_headers.py` | 128 | Análise de headers de segurança |
| `port_scan.py` | 126 | TCP connect + banner grab paralelo |

---

## Requisitos

| Requisito | Versão |
|-----------|--------|
| Python | 3.10 ou superior |
| Sistema operacional | Linux (qualquer distro) |
| Privilégios | usuário comum (sem root) |
| Dependências externas | **nenhuma** |
| Conexão com internet | necessária para crt.sh e WHOIS |

> O DomainSpecter **não requer root** — diferente de ferramentas que usam raw sockets para sniffing, aqui usamos TCP connect scan e requisições HTTP normais.

---

## Instalação

```bash
# Clone o repositório
git clone https://github.com/SrElliX/domainspecter.git

# Entre na pasta
cd domainspecter

# Nenhuma instalação necessária — Python puro!
python3 --version   # confirme 3.10+
```

---

## Como usar

### Uso básico

```bash
# Reconhecimento passivo (padrão quando nenhum módulo é passado)
python3 specter.py -d example.com

# Tudo de uma vez
python3 specter.py -d example.com --all

# Salvar resultado em JSON
python3 specter.py -d example.com --all --output resultado.json
```

### Módulos individuais

```bash
# Só WHOIS
python3 specter.py -d example.com --whois

# WHOIS + DNS
python3 specter.py -d example.com --whois --dns

# Subdomínios
python3 specter.py -d example.com --subdomains

# Port scan
python3 specter.py -d example.com --ports

# HTTP headers
python3 specter.py -d example.com --headers

# E-mails expostos
python3 specter.py -d example.com --emails
```

### Combinações úteis

```bash
# Fase passiva completa (não toca no alvo)
python3 specter.py -d example.com --whois --dns --subdomains

# Fase ativa
python3 specter.py -d example.com --ports --headers --emails

# Scan completo com timeout reduzido e saída JSON
python3 specter.py -d example.com --all --timeout 3 --output scan.json
```

> **Dica:** para testes seguros, use `example.com` — domínio reservado pela IANA para documentação.

---

## Módulos

### WHOIS Lookup

**Arquivo:** `modules/whois_lookup.py`

Consulta o servidor WHOIS responsável pelo TLD do domínio via **socket TCP raw na porta 43**. O protocolo WHOIS é simples: envia o domínio seguido de `\r\n` e recebe a resposta em texto plano. Nenhuma biblioteca externa — implementado manualmente com `socket`.

**O que coleta:**
- Registrar (empresa que registrou o domínio)
- Data de criação, expiração e última atualização
- Nameservers autoritativos
- Organização e país do registrante
- E-mails expostos no registro WHOIS
- Status do domínio (clientTransferProhibited, etc.)

**Como funciona internamente:**

```python
# Protocolo WHOIS — porta 43, TCP
with socket.create_connection((whois_server, 43), timeout=5) as sock:
    sock.sendall(f"{domain}\r\n".encode())
    response = b""
    while chunk := sock.recv(4096):
        response += chunk
```

Os campos são extraídos com **expressões regulares** sobre o texto retornado, pois não há formato padronizado entre registros — cada servidor WHOIS retorna um layout diferente.

---

### DNS Recon

**Arquivo:** `modules/dns_recon.py`

Consulta registros DNS diretamente via **socket UDP raw na porta 53**, montando e desmontando os pacotes manualmente com `struct.pack` / `struct.unpack`. Implementação do protocolo DNS (RFC 1035) do zero.

**Registros consultados:** `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME` e DNS reverso.

**Estrutura de um pacote DNS montado manualmente:**

```
Pacote DNS Query (bytes)
├── Header (12 bytes)
│   ├── Transaction ID  [2B] — identificador aleatório
│   ├── Flags           [2B] — 0x0100 = recursão desejada
│   ├── QDCOUNT         [2B] — número de perguntas (1)
│   └── ANCOUNT/...     [6B] — zeros
│
└── Question Section
    ├── QNAME   — domínio codificado em labels
    │             "example.com" → \x07example\x03com\x00
    ├── QTYPE   [2B] — tipo do registro (1=A, 15=MX...)
    └── QCLASS  [2B] — 1 = Internet
```

O parser da resposta implementa **ponteiros de compressão DNS** (RFC 1035 §4.1.4) — quando o servidor comprime nomes repetidos usando um ponteiro de 2 bytes com os bits mais significativos `11`.

---

### Subdomain Enumeration

**Arquivo:** `modules/subdomains.py`

Usa duas estratégias complementares:

**1. Certificate Transparency Logs (passivo)**

Consulta a API pública do [crt.sh](https://crt.sh), que indexa todos os certificados SSL/TLS emitidos publicamente. Cada certificado registra os domínios para os quais foi emitido — subdomínios aparecem ali sem que o alvo perceba que está sendo pesquisado.

```
https://crt.sh/?q=%.example.com&output=json
```

**2. Bruteforce por wordlist (ativo)**

Testa ~60 subdomínios comuns tentando resolver no DNS usando `ThreadPoolExecutor` com 30 workers em paralelo.

```python
with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
    futures = {executor.submit(resolve_subdomain, sub): sub for sub in candidates}
```

**Subdomínios testados incluem:** `www`, `mail`, `api`, `dev`, `staging`, `admin`, `vpn`, `git`, `jenkins`, `grafana`, `kibana`, `db`, `redis`, `mongo`, e outros ~45 candidatos comuns.

---

### Port Scanner

**Arquivo:** `modules/port_scan.py`

**TCP Connect Scan** nas portas mais relevantes de servidores web e aplicações. Diferente de um SYN scan (que requer raw socket e root), o connect scan completa o handshake TCP — funciona sem privilégios elevados.

Após conectar, tenta capturar o **banner** do serviço — SSH, FTP e SMTP enviam automaticamente sua versão ao receber uma conexão; servidores HTTP respondem a um `HEAD /`.

**Portas verificadas (39 portas):**

```
21(FTP)  22(SSH)  23(Telnet)  25(SMTP)  53(DNS)   80(HTTP)
110(POP3) 143(IMAP) 443(HTTPS) 445(SMB) 3306(MySQL)
3389(RDP) 5432(PostgreSQL) 5900(VNC) 6379(Redis)
8080(HTTP-alt) 8443(HTTPS-alt) 9200(Elasticsearch)
27017(MongoDB) ... e mais
```

O scan usa `ThreadPoolExecutor` com 50 workers — varrer 39 portas sequencialmente com 3s de timeout cada levaria ~117s; em paralelo, leva ~3-5s.

---

### HTTP Headers Analysis

**Arquivo:** `modules/http_headers.py`

Faz uma requisição `HEAD` e analisa os headers de resposta em duas dimensões:

**1. Fingerprinting de tecnologia**

| Header | O que revela |
|--------|-------------|
| `Server` | Software do servidor (nginx/1.18, Apache/2.4...) |
| `X-Powered-By` | Linguagem/framework (PHP/8.1, Express...) |
| `X-Generator` | CMS utilizado (WordPress, Drupal...) |
| `Via` | Proxies e CDNs intermediários |
| `CF-Ray` | Presença de Cloudflare |
| `X-Varnish` | Cache Varnish |

**2. Auditoria de segurança**

| Header | Protege contra |
|--------|---------------|
| `Strict-Transport-Security` | Downgrade para HTTP |
| `Content-Security-Policy` | XSS e injeção de conteúdo |
| `X-Frame-Options` | Clickjacking |
| `X-Content-Type-Options` | MIME type sniffing |
| `Referrer-Policy` | Vazamento de URL em referências |
| `Permissions-Policy` | Abuso de APIs do browser |

Também analisa **flags de segurança dos cookies** (`HttpOnly`, `Secure`, `SameSite`).

---

### Email Harvesting

**Arquivo:** `modules/email_harvest.py`

Combina três fontes para descobrir e-mails expostos:

**1. Registro SPF (DNS TXT)**

O registro SPF revela os provedores de e-mail usados pelo domínio — informação valiosa para engenharia social e spear phishing simulado:

```
v=spf1 include:_spf.google.com include:mailchimp.com ~all
        ↑ Google Workspace           ↑ Mailchimp
```

**2. Scraping de páginas públicas**

Busca e-mails nas rotas `/contact`, `/about`, `/team`, `/support`, `/imprint` com regex e filtra pelo domínio alvo.

**3. Formatos corporativos inferidos**

Mesmo sem encontrar e-mails reais, gera os padrões mais comuns:

```
nome.sobrenome@alvo.com    n.sobrenome@alvo.com
nome@alvo.com              contact@alvo.com
admin@alvo.com             security@alvo.com
```

---

## Exemplos de saída

### Reconhecimento completo

```bash
python3 specter.py -d example.com --all
```

```
██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗
...
        DomainSpecter — OSINT Recon Tool
             by SrElliX

Alvo:     example.com
Início:   2024-11-15 14:32:01
Timeout:  5s

────────────────────────────────────────────────────────────
  WHOIS Lookup
────────────────────────────────────────────────────────────
  Servidor WHOIS: whois.verisign-grs.com
  Registrar      ICANN
  Criado em      1995-08-14T04:00:00Z
  Expira em      2025-08-13T04:00:00Z
  País           US

  Name Servers:
    • a.iana-servers.net
    • b.iana-servers.net

────────────────────────────────────────────────────────────
  DNS Reconnaissance
────────────────────────────────────────────────────────────
  A        • 93.184.216.34
  AAAA     • 2606:2800:220:1:248:1893:25c8:1946
  MX       (sem registros)
  NS       • a.iana-servers.net
           • b.iana-servers.net
  TXT      • v=spf1 -all

────────────────────────────────────────────────────────────
  Port Scan
────────────────────────────────────────────────────────────
  IP resolvido: 93.184.216.34
  Escaneando 39 portas com 50 threads...

  [+] 2 porta(s) abertas:

  PORTA    SERVIÇO            BANNER
  ────────────────────────────────────────────────────────
  80       HTTP               HTTP/1.1 200 OK
  443      HTTPS              HTTP/1.1 200 OK

────────────────────────────────────────────────────────────
  HTTP Headers Analysis
────────────────────────────────────────────────────────────
  Requisição HEAD → https://example.com
  Status: 200

  Tecnologias identificadas:
    • Server: ECS (dcb/7EC7)
    • Via: 1.1 varnish

  Headers de segurança:
    [OK] Strict-Transport-Security
    [--] Content-Security-Policy         (CSP — previne XSS)
    [OK] X-Content-Type-Options
    [--] X-Frame-Options                 (previne clickjacking)
    [--] Referrer-Policy                 (controla referência)
```

### Saída JSON (`--output resultado.json`)

```json
{
  "target": "example.com",
  "timestamp": "2024-11-15 14:32:01",
  "modules": {
    "whois": {
      "registrar": "ICANN",
      "creation_date": "1995-08-14T04:00:00Z",
      "expiry_date": "2025-08-13T04:00:00Z",
      "name_servers": ["a.iana-servers.net", "b.iana-servers.net"],
      "registrant_country": "US"
    },
    "dns": {
      "A": ["93.184.216.34"],
      "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
      "TXT": ["v=spf1 -all"]
    },
    "ports": {
      "target_ip": "93.184.216.34",
      "open_ports": [
        {"port": 80,  "service": "HTTP",  "banner": "HTTP/1.1 200 OK"},
        {"port": 443, "service": "HTTPS", "banner": "HTTP/1.1 200 OK"}
      ]
    }
  }
}
```

---

## Arquitetura do código

```
specter.py  (orquestrador)
│
├── Lê argumentos CLI (argparse)
├── Executa módulos em sequência: passivo → ativo → relatório
│
├── modules/whois_lookup.py
│   ├── query_whois()        — socket TCP porta 43
│   ├── parse_whois()        — regex sobre texto livre
│   └── run_whois()          — entrada pública do módulo
│
├── modules/dns_recon.py
│   ├── build_dns_query()    — monta pacote UDP com struct.pack
│   ├── parse_dns_name()     — decodifica labels + ponteiros de compressão
│   ├── parse_dns_response() — extrai registros da resposta
│   ├── query_dns()          — envia/recebe via socket UDP
│   └── run_dns()            — itera todos os tipos de registro
│
├── modules/subdomains.py
│   ├── fetch_crtsh()            — HTTP GET na API crt.sh
│   ├── resolve_subdomain()      — gethostbyname unitário
│   ├── bruteforce_subdomains()  — ThreadPoolExecutor (30 workers)
│   └── run_subdomains()
│
├── modules/port_scan.py
│   ├── grab_banner()   — recv após TCP connect
│   ├── scan_port()     — TCP connect + banner
│   └── run_portscan()  — ThreadPoolExecutor (50 workers)
│
├── modules/http_headers.py
│   ├── fetch_headers()      — urllib HEAD request
│   └── run_http_headers()   — fingerprint + auditoria de segurança
│
├── modules/email_harvest.py
│   ├── fetch_page()             — urllib GET
│   ├── extract_emails_from_text() — regex
│   ├── analyze_spf()            — reutiliza dns_recon
│   ├── infer_email_format()     — padrões corporativos
│   └── run_email_harvest()
│
└── modules/report.py
    └── generate_report()   — consolida resultados em terminal/arquivo
```

### Padrão de design

Cada módulo expõe uma função `run_*()` com a mesma assinatura:

```python
def run_modulo(domain: str, timeout: int = 5) -> dict:
    # coleta dados...
    return { ... }   # sempre retorna dict com os achados
```

O orquestrador chama cada `run_*()`, acumula os resultados num único dict e passa para `generate_report()`. Adicionar um novo módulo é simples: cria o arquivo, implementa o `run_*()` e registra em `specter.py`.

---

## Flags e argumentos

```
uso: specter.py [-h] -d DOMAIN [--all] [--whois] [--dns]
                [--subdomains] [--ports] [--headers] [--emails]
                [--output OUTPUT] [--timeout TIMEOUT]
```

| Argumento | Tipo | Descrição |
|-----------|------|-----------|
| `-d`, `--domain` | string | **Obrigatório.** Domínio alvo |
| `--all` | flag | Executa todos os módulos |
| `--whois` | flag | Módulo WHOIS lookup |
| `--dns` | flag | Módulo DNS recon |
| `--subdomains` | flag | Módulo subdomain enumeration |
| `--ports` | flag | Módulo port scanner |
| `--headers` | flag | Módulo HTTP headers |
| `--emails` | flag | Módulo email harvesting |
| `--output`, `-o` | string | Salvar relatório (`.json` ou `.txt`) |
| `--timeout` | inteiro | Timeout de rede em segundos (padrão: `5`) |

**Comportamento padrão:** se nenhum módulo for passado, executa automaticamente `--whois --dns --subdomains` (reconhecimento passivo).

**O formato da saída é inferido pela extensão:**

```bash
--output resultado.json   # salva JSON estruturado
--output resultado.txt    # salva relatório em texto puro
```

---

## Aviso legal

> ⚠️ **Este projeto é estritamente educacional.**
>
> O uso de ferramentas de reconhecimento e coleta de informações **sem autorização explícita** é ilegal em muitos países e pode violar legislações como:
> - **Brasil:** Lei nº 12.737/2012 (Lei Carolina Dieckmann) e LGPD
> - **EUA:** Computer Fraud and Abuse Act (CFAA)
> - **Europa:** Computer Misuse Act e regulações similares
>
> Use o DomainSpecter **somente em:**
> - Seus próprios domínios e infraestrutura
> - Ambientes de laboratório e CTFs (Capture The Flag)
> - Alvos para os quais você possui **autorização por escrito**
> - Plataformas de prática como HackTheBox, TryHackMe ou VulnHub
>
> O autor não se responsabiliza por qualquer uso indevido desta ferramenta.

---

## Próximos passos

- [ ] Exportação em formato `.pdf` com relatório visual
- [ ] Parsing de DNS sobre HTTPS (DoH) para bypass de filtros
- [ ] Detecção de WAF (Web Application Firewall)
- [ ] Análise de certificado SSL (validade, cipher suites, SANs)
- [ ] Descoberta de arquivos sensíveis expostos (`.git`, `.env`, `robots.txt`)
- [ ] Interface web com Flask para visualização em tempo real
- [ ] Integração com Have I Been Pwned API para e-mails vazados
- [ ] Modo silencioso com rate limiting para evitar alertas de IDS
- [ ] Suporte a IPv6

---

## Referências técnicas

- [RFC 3912 — WHOIS Protocol](https://www.rfc-editor.org/rfc/rfc3912)
- [RFC 1035 — Domain Names (DNS)](https://www.rfc-editor.org/rfc/rfc1035)
- [RFC 7208 — Sender Policy Framework (SPF)](https://www.rfc-editor.org/rfc/rfc7208)
- [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110)
- [RFC 6962 — Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962)
- [OWASP — Testing for Information Gathering](https://owasp.org/www-project-web-security-testing-guide/)
- [Python docs — socket module](https://docs.python.org/3/library/socket.html)
- [Python docs — struct module](https://docs.python.org/3/library/struct.html)
- [Python docs — concurrent.futures](https://docs.python.org/3/library/concurrent.futures.html)
- [crt.sh — Certificate Search](https://crt.sh)

---

<div align="center">

Feito por <a href="https://github.com/SrElliX">SrElliX</a> &nbsp;•&nbsp; Projeto educacional de cibersegurança

<sub>Use com responsabilidade. Reconhecimento só em alvos autorizados.</sub>

</div>
