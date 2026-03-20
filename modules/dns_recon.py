"""
Módulo DNS Recon
Consulta registros DNS diretamente com socket UDP — sem dnspython.
Implementado manualmente para fins educacionais.
"""

import socket
import struct
import random

RESET  = "\033[0m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"

# Tipos de registro DNS que vamos consultar
DNS_TYPES = {
    "A":     1,
    "NS":    2,
    "MX":   15,
    "TXT":  16,
    "AAAA": 28,
    "CNAME": 5,
}

DNS_SERVER = "8.8.8.8"   # Google Public DNS


def build_dns_query(domain: str, qtype: int) -> bytes:
    """
    Monta um pacote de query DNS manualmente.
    Formato: Header (12B) + Question Section
    """
    # Header: ID aleatório | FLAGS (query padrão) | QDCOUNT=1 | 0 0 0
    transaction_id = random.randint(0, 65535)
    flags     = 0x0100   # recursão desejada
    qdcount   = 1
    header    = struct.pack("!HHHHHH", transaction_id, flags, qdcount, 0, 0, 0)

    # Question: codifica o domínio no formato DNS (labels)
    # "example.com" → \x07example\x03com\x00
    question = b""
    for part in domain.split("."):
        question += bytes([len(part)]) + part.encode()
    question += b"\x00"                            # fim do nome
    question += struct.pack("!HH", qtype, 1)       # QTYPE + QCLASS (IN)

    return header + question


def parse_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """
    Decodifica um nome DNS com suporte a compressão de ponteiros (RFC 1035).
    Retorna (nome, novo_offset).
    """
    labels = []
    visited = set()

    while True:
        if offset >= len(data):
            break
        length = data[offset]

        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            # Ponteiro de compressão: próximos 14 bits = offset real
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if ptr in visited:
                break
            visited.add(ptr)
            name, _ = parse_dns_name(data, ptr)
            labels.append(name)
            offset += 2
            break
        else:
            offset += 1
            labels.append(data[offset:offset + length].decode(errors="replace"))
            offset += length

    return ".".join(labels), offset


def parse_dns_response(data: bytes, qtype: int) -> list[str]:
    """Extrai os registros de resposta de um pacote DNS."""
    if len(data) < 12:
        return []

    ancount = struct.unpack("!H", data[6:8])[0]   # número de respostas
    if ancount == 0:
        return []

    # Pula o header (12B) e a seção de pergunta
    offset = 12
    # Pula a question section
    while offset < len(data) and data[offset] != 0:
        if (data[offset] & 0xC0) == 0xC0:
            offset += 2
            break
        offset += data[offset] + 1
    else:
        offset += 1
    offset += 4   # QTYPE + QCLASS

    records = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        _, offset = parse_dns_name(data, offset)

        if offset + 10 > len(data):
            break

        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength

        if rtype == 1 and len(rdata) == 4:           # A
            records.append(socket.inet_ntoa(rdata))
        elif rtype == 28 and len(rdata) == 16:        # AAAA
            records.append(socket.inet_ntop(socket.AF_INET6, rdata))
        elif rtype in (2, 5, 15):                     # NS, CNAME, MX
            start = 2 if rtype == 15 else 0           # MX tem 2B de preference
            name, _ = parse_dns_name(data, offset - rdlength + start)
            records.append(name)
        elif rtype == 16:                             # TXT
            txt = ""
            pos = 0
            while pos < len(rdata):
                length = rdata[pos]
                txt += rdata[pos + 1:pos + 1 + length].decode(errors="replace")
                pos += 1 + length
            records.append(txt)

    return records


def query_dns(domain: str, qtype_name: str, timeout: int = 5) -> list[str]:
    """Envia query DNS via UDP e retorna os registros."""
    qtype = DNS_TYPES.get(qtype_name, 1)
    packet = build_dns_query(domain, qtype)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (DNS_SERVER, 53))
            response, _ = sock.recvfrom(4096)
        return parse_dns_response(response, qtype)
    except socket.timeout:
        return []
    except Exception:
        return []


def run_dns(domain: str, timeout: int = 5) -> dict:
    results = {}

    type_colors = {
        "A":     GREEN,
        "AAAA":  CYAN,
        "MX":    YELLOW,
        "NS":    CYAN,
        "TXT":   GRAY,
        "CNAME": YELLOW,
    }

    for record_type in DNS_TYPES:
        records = query_dns(domain, record_type, timeout)
        results[record_type] = records

        col = type_colors.get(record_type, RESET)
        if records:
            print(f"  {BOLD}{record_type:<6}{RESET}")
            for r in records:
                # Trunca TXT longo
                display = r if len(r) <= 80 else r[:77] + "..."
                print(f"    {col}•{RESET} {display}")
        else:
            print(f"  {BOLD}{record_type:<6}{RESET} {GRAY}(sem registros){RESET}")

    # Tenta também reverso do IP principal
    a_records = results.get("A", [])
    if a_records:
        try:
            hostname = socket.gethostbyaddr(a_records[0])[0]
            results["reverse_dns"] = hostname
            print(f"\n  {BOLD}Reverso ({a_records[0]}):{RESET} {hostname}")
        except Exception:
            results["reverse_dns"] = None

    return results
