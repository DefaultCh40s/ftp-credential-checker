#!/usr/bin/env python3
"""
FTP Checker - Testa credenciais FTP no formato HOST:USER:PASS

Novidades v2.0:
  - --check-web : testa HTTP/HTTPS após login válido + detecta WebRoot provável
  - --log       : arquivo de log de processo (separado do -o de válidos)
  - resumo com tempos, taxa de sucesso e top falhas
  - barra de progresso em tempo real
  - linhas inválidas contabilizadas
  - escrita thread-safe no arquivo de saída
  - sem variáveis globais (contexto via dataclass)

Uso:
  python3 ftp_checker.py -f lista.txt -t 10 -o validos.txt --log processo.log
  python3 ftp_checker.py -f lista.txt --check-web -o validos.txt
"""

import ftplib
import argparse
import sys
import os
import socket
import http.client
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from dataclasses import dataclass, field
from collections import Counter

# ---------------------------------------------------------------------------
# Cores ANSI
# ---------------------------------------------------------------------------
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

# Indícios de que o PWD do FTP aponta para um document root web
WEB_ROOT_HINTS = ("public_html", "www", "htdocs", "html", "webroot", "var/www", "/web")


# ---------------------------------------------------------------------------
# Banner (ASCII corrigido)
# ---------------------------------------------------------------------------
def banner():
    print(f"""{CYAN}{BOLD}
  ███████╗████████╗██████╗       ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗
  ██╔════╝╚══██╔══╝██╔══██╗     ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗
  █████╗     ██║   ██████╔╝     ██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝
  ██╔══╝     ██║   ██╔═══╝      ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗
  ██║        ██║   ██║          ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║
  ╚═╝        ╚═╝   ╚═╝           ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
{RESET}{YELLOW}  [*] FTP Credential Checker v2.0 | Formato: HOST:USER:PASS
{RESET}""")


# ---------------------------------------------------------------------------
# Contexto compartilhado (substitui a global args_global)
# ---------------------------------------------------------------------------
@dataclass
class Ctx:
    port: int
    timeout: int
    output_file: str
    check_web: bool
    logger: logging.Logger
    stats: dict = field(default_factory=lambda: {
        "total": 0,
        "valid": 0,
        "invalid": 0,
        "skipped": 0,
        "webroot_hits": 0,
        "fail_reasons": Counter(),
    })
    stats_lock: threading.Lock = field(default_factory=threading.Lock)
    file_lock: threading.Lock = field(default_factory=threading.Lock)
    start_time: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
def parse_line(line: str):
    """Parseia linha no formato HOST:USER:PASS. Retorna (host, user, pass) ou None."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split(":")
    if len(parts) < 3:
        return None
    host = parts[0].strip()
    user = parts[1].strip()
    password = ":".join(parts[2:]).strip()
    if not host:
        return None
    return host, user, password


# ---------------------------------------------------------------------------
# Verificação FTP
# ---------------------------------------------------------------------------
def check_ftp(host: str, user: str, password: str, port: int, timeout: int):
    """
    Tenta autenticar via FTP.
    Retorna (True, dict_info) em sucesso, (False, motivo) em falha.
    """
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=timeout)
        ftp.login(user, password)

        try:
            welcome = ftp.getwelcome()
        except Exception:
            welcome = "N/A"
        try:
            pwd = ftp.pwd()
        except Exception:
            pwd = "N/A"
        try:
            files = ftp.nlst()[:5]
            listing = ", ".join(files) if files else "(vazio)"
        except Exception:
            listing = "N/A"

        try:
            ftp.quit()
        except Exception:
            pass

        return True, {"welcome": welcome, "pwd": pwd, "listing": listing}

    except ftplib.error_perm as e:
        return False, f"Credenciais inválidas: {e}"
    except ftplib.error_temp as e:
        return False, f"Erro temporário: {e}"
    except ConnectionRefusedError:
        return False, "Conexão recusada"
    except TimeoutError:
        return False, "Timeout"
    except socket.timeout:
        return False, "Timeout"
    except OSError as e:
        return False, f"Erro de rede: {e}"
    except Exception as e:
        return False, f"Erro: {type(e).__name__}: {e}"


# ---------------------------------------------------------------------------
# Verificação web (HTTP/HTTPS)
# ---------------------------------------------------------------------------
def check_web(host: str, timeout: int = 3):
    """Testa HTTP (80) e HTTPS (443). Retorna dict com status."""
    result = {"http": False, "https": False, "server": None, "status": None}
    for scheme, port, key in (("http", 80, "http"), ("https", 443, "https")):
        try:
            if scheme == "https":
                conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                                   context=_insecure_ctx())
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request("HEAD", "/")
            resp = conn.getresponse()
            result[key] = True
            if result["server"] is None:
                result["server"] = resp.getheader("Server")
                result["status"] = resp.status
            conn.close()
        except Exception:
            pass
    return result


def _insecure_ctx():
    """Contexto SSL que não valida certificado (comum em painéis internos)."""
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def looks_like_webroot(pwd: str) -> bool:
    if not pwd:
        return False
    p = pwd.lower()
    return any(h in p for h in WEB_ROOT_HINTS)


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------
def worker(entry: str, line_no: int, ctx: Ctx):
    parsed = parse_line(entry)
    if not parsed:
        with ctx.stats_lock:
            ctx.stats["skipped"] += 1
        ctx.logger.warning("Linha %d ignorada (formato inválido): %r", line_no, entry.strip())
        return

    host, user, password = parsed
    success, info = check_ftp(host, user, password, ctx.port, ctx.timeout)

    if not success:
        with ctx.stats_lock:
            ctx.stats["total"] += 1
            ctx.stats["invalid"] += 1
            # Normaliza motivo para agrupamento
            reason = info.split(":")[0].strip() if isinstance(info, str) else "Erro"
            ctx.stats["fail_reasons"][reason] += 1
        ctx.logger.debug("FALHOU | %s | %s:%s | %s", host, user, password, info)
        return

    # ---- Sucesso ----
    web_info = None
    webroot = False
    if ctx.check_web:
        web_info = check_web(host, timeout=3)
        webroot = looks_like_webroot(info["pwd"])

    with ctx.stats_lock:
        ctx.stats["total"] += 1
        ctx.stats["valid"] += 1
        if webroot:
            ctx.stats["webroot_hits"] += 1

    # Log de processo
    ctx.logger.info(
        "VÁLIDO | %s | %s:%s | PWD=%s | Files=%s | Web=%s | WebRoot=%s",
        host, user, password, info["pwd"], info["listing"],
        web_info if web_info else "-",
        "SIM" if webroot else "não",
    )

    # Saída colorida no terminal
    web_str = ""
    if web_info:
        http_ok = "✓" if web_info["http"] else "✗"
        https_ok = "✓" if web_info["https"] else "✗"
        srv = f" ({web_info['status']}, {web_info['server']})" if web_info["server"] else ""
        web_str = f" | Web: HTTP={http_ok} HTTPS={https_ok}{srv}"
        if webroot:
            web_str += f" | {GREEN}WebRoot provável{RESET}"

    line = (
        f"{GREEN}[+] VÁLIDO{RESET} | {BOLD}{host}{RESET} | "
        f"User: {user} | Pass: {password} | PWD: {info['pwd']} | "
        f"Files: {info['listing']}{web_str}"
    )
    print(line)

    # Escrita thread-safe no arquivo de válidos
    if ctx.output_file:
        extra = ""
        if web_info:
            extra = f" | HTTP={'on' if web_info['http'] else 'off'}"
            extra += f" | HTTPS={'on' if web_info['https'] else 'off'}"
            extra += f" | WebRoot={'yes' if webroot else 'no'}"
        row = f"{host}:{user}:{password} | PWD={info['pwd']} | Files={info['listing']}{extra}\n"
        with ctx.file_lock:
            with open(ctx.output_file, "a", encoding="utf-8") as f:
                f.write(row)


# ---------------------------------------------------------------------------
# Progresso
# ---------------------------------------------------------------------------
def render_progress(done: int, total: int, valid: int, skipped: int):
    pct = (done / total * 100) if total else 0
    sys.stdout.write(
        f"\r{CYAN}[*] Progresso: {done}/{total} ({pct:5.1f}%) | "
        f"Válidos: {GREEN}{valid}{RESET} | Ignorados: {skipped}{RESET}   "
    )
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
def setup_logger(log_path: str, quiet: bool) -> logging.Logger:
    logger = logging.getLogger("ftpchecker")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-7s | %(message)s"))
    logger.addHandler(fh)

    if not quiet:
        sh = logging.StreamHandler(sys.stderr)
        sh.setLevel(logging.INFO)
        sh.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(sh)

    return logger


# ---------------------------------------------------------------------------
# Resumo
# ---------------------------------------------------------------------------
def print_summary(ctx: Ctx):
    s = ctx.stats
    elapsed = time.time() - ctx.start_time
    testados = s["total"]
    taxa = (s["valid"] / testados * 100) if testados else 0
    media = (elapsed / testados) if testados else 0

    print("\n" + "-" * 80)
    print(f"{BOLD}[*] Resumo Final{RESET}")
    print(f"    Testados         : {testados}")
    print(f"    {GREEN}Válidos          : {s['valid']} ({taxa:.1f}%){RESET}")
    print(f"    {RED}Inválidos        : {s['invalid']}{RESET}")
    print(f"    Ignorados        : {s['skipped']} (formato inválido)")
    if ctx.check_web:
        print(f"    WebRoot provável : {s['webroot_hits']}")
    print(f"    Tempo total      : {int(elapsed // 60):02d}:{int(elapsed % 60):02d}")
    print(f"    Tempo médio/tent : {media:.2f}s")

    if s["fail_reasons"]:
        print(f"    Top falhas:")
        for reason, count in s["fail_reasons"].most_common(5):
            print(f"      {reason:<30} : {count}")

    if ctx.output_file and s["valid"] > 0:
        print(f"    {GREEN}Resultados salvos em: {ctx.output_file}{RESET}")
    print(f"[*] Fim: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    banner()

    parser = argparse.ArgumentParser(
        description="FTP Checker v2.0 - Testa listas de credenciais FTP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python3 ftp_checker.py -f lista.txt
  python3 ftp_checker.py -f lista.txt -t 20 -o validos.txt --log processo.log
  python3 ftp_checker.py -f lista.txt -p 2121 --timeout 5 -q
  python3 ftp_checker.py -f lista.txt --check-web -o validos.txt
  echo "192.168.1.1:admin:admin" | python3 ftp_checker.py --stdin
        """
    )
    parser.add_argument("-f", "--file", help="Arquivo com lista HOST:USER:PASS")
    parser.add_argument("--stdin", action="store_true", help="Ler da stdin")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Threads (default: 10)")
    parser.add_argument("-p", "--port", type=int, default=21, help="Porta FTP (default: 21)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout em segundos (default: 10)")
    parser.add_argument("-o", "--output", help="Arquivo para salvar credenciais válidas")
    parser.add_argument("--log", default="ftp_checker.log",
                        help="Arquivo de log de processo (default: ftp_checker.log)")
    parser.add_argument("--check-web", action="store_true",
                        help="Após login válido, testar HTTP/HTTPS e detectar WebRoot provável")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suprimir falhas no terminal (ainda grava no --log)")

    args = parser.parse_args()

    # ---- Leitura das entradas ----
    lines = []
    if args.file:
        if not os.path.isfile(args.file):
            print(f"{RED}[!] Arquivo não encontrado: {args.file}{RESET}")
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    elif args.stdin:
        lines = sys.stdin.readlines()
    else:
        parser.print_help()
        sys.exit(1)

    # Remove linhas vazias para contagem, mas mantém numeração original
    indexed_lines = [(i + 1, l) for i, l in enumerate(lines) if l.strip() and not l.startswith("#")]
    total_entries = len(indexed_lines)

    if total_entries == 0:
        print(f"{YELLOW}[!] Nenhuma entrada válida para processar.{RESET}")
        sys.exit(1)

    # ---- Logger ----
    logger = setup_logger(args.log, args.quiet)

    # ---- Cabeçalho ----
    print(f"{CYAN}[*] Entradas carregadas : {total_entries}")
    print(f"[*] Threads             : {args.threads}")
    print(f"[*] Porta FTP           : {args.port}")
    print(f"[*] Timeout             : {args.timeout}s")
    print(f"[*] Output (válidos)    : {args.output or 'Nenhum'}")
    print(f"[*] Log de processo     : {args.log}")
    print(f"[*] Check Web           : {'sim' if args.check_web else 'não'}")
    print(f"[*] Início              : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print("-" * 80)

    logger.info("=== FTP Checker v2.0 iniciado ===")
    logger.info("Entradas=%d Threads=%d Porta=%d Timeout=%ds CheckWeb=%s",
                total_entries, args.threads, args.port, args.timeout, args.check_web)

    # ---- Prepara arquivo de válidos ----
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(f"# FTP Checker v2.0 - {datetime.now()}\n")

    # ---- Contexto ----
    ctx = Ctx(
        port=args.port,
        timeout=args.timeout,
        output_file=args.output,
        check_web=args.check_web,
        logger=logger,
    )

    # ---- Execução paralela ----
    done = 0
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(worker, line, line_no, ctx): line_no
                for line_no, line in indexed_lines
            }
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error("Erro no worker: %s", e)
                done += 1
                with ctx.stats_lock:
                    valid = ctx.stats["valid"]
                    skipped = ctx.stats["skipped"]
                render_progress(done, total_entries, valid, skipped)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrompido pelo usuário.{RESET}")
        logger.warning("Interrompido pelo usuário.")

    print()  # nova linha após a barra de progresso
    print_summary(ctx)
    logger.info("=== FTP Checker v2.0 finalizado ===")


if __name__ == "__main__":
    main()