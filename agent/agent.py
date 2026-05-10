"""
Sentinel360 – Agente Remoto v2
Instalável em qualquer máquina (Windows / Linux / macOS).
Faz varredura local e envia resultados para a API central.

Instalação:
    pip install sentinel360-agent
    s360-agent install --api-url https://sentinel360.onrender.com --agent-key s360_xxx

Como daemon (Linux):
    s360-agent service install
    systemctl start sentinel360

Como serviço (Windows):
    s360-agent service install   # requer pywin32
    sc start sentinel360
"""
from __future__ import annotations

import os
import sys
import time
import json
import asyncio
import hashlib
import platform
import argparse
import logging
import signal
from pathlib import Path
from typing import List, Optional, Generator
from datetime import datetime, timedelta

import httpx

# ─── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(Path.home() / ".sentinel360" / "agent.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("sentinel360-agent")

# ─── Config ──────────────────────────────────────────────────────────────────

CONFIG_FILE = Path.home() / ".sentinel360" / "config.json"

IGNORE_DIRS = {
    # Windows
    "Windows", "System32", "SysWOW64", "WinSxS", "AppData",
    "$Recycle.Bin", "Recovery", "ProgramData",
    # Linux/macOS
    "proc", "sys", "dev", "run", "snap", "boot",
    # Ferramentas
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".cache", ".npm",
}

TEXT_EXTENSIONS = {
    ".txt", ".log", ".conf", ".ini", ".py", ".js", ".ts", ".jsx", ".tsx",
    ".json", ".sql", ".env", ".xml", ".yaml", ".yml", ".csv", ".md", ".sh",
    ".rb", ".php", ".java", ".go", ".rs", ".toml", ".cfg", ".properties",
    ".htaccess", ".gitignore", ".dockerignore",
}

BATCH_SIZE     = 200   # quantos resultados enviar por request
SCAN_INTERVAL  = 3600  # segundos entre scans agendados (1h)
MAX_FILE_READ  = 8192  # bytes lidos por arquivo para análise


# ─── Configuração persistente ────────────────────────────────────────────────

def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}

def save_config(cfg: dict):
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)
    log.info(f"Config salva em {CONFIG_FILE}")


# ─── Scanner ─────────────────────────────────────────────────────────────────

import re

SENSITIVE_PATTERNS = {
    "CPF":           r"\d{3}\.?\d{3}\.?\d{3}-?\d{2}",
    "CNPJ":          r"\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}",
    "Chave Privada": r"-----BEGIN (RSA|OPENSSH|EC|PRIVATE) KEY-----",
    "Token/Secret":  r"(?i)(password|secret|token|api_?key|passwd)\s*[=:]\s*\S+",
    "AWS Key":       r"AKIA[0-9A-Z]{16}",
    "JWT":           r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
    "Cartão":        r"\b(?:\d{4}[\s\-]?){3}\d{4}\b",
}

RISK_PRIORITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
RISK_MAP = {
    "CPF": "critical", "CNPJ": "high", "Chave Privada": "critical",
    "AWS Key": "critical", "JWT": "high", "Token/Secret": "high", "Cartão": "critical",
}


def scan_content(content: str) -> List[dict]:
    findings = []
    for label, pattern in SENSITIVE_PATTERNS.items():
        if re.search(pattern, content):
            findings.append({"type": label, "confidence": 1.0, "detected_by": "regex"})
    return findings


def get_risk_level(findings: List[dict]) -> str:
    if not findings:
        return "none"
    highest = "none"
    for f in findings:
        rl = RISK_MAP.get(f["type"], "medium")
        if RISK_PRIORITY.get(rl, 0) > RISK_PRIORITY.get(highest, 0):
            highest = rl
    return highest


def analyze_file(path: Path, threshold_seconds: float) -> Optional[dict]:
    try:
        stat         = path.stat()
        now          = time.time()
        is_inactive  = (now - stat.st_atime) > threshold_seconds
        findings     = []

        if path.suffix.lower() in TEXT_EXTENSIONS:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(MAX_FILE_READ)
            findings = scan_content(content)

        risk_level = get_risk_level(findings)

        if not is_inactive and risk_level == "none":
            return None  # nada relevante

        return {
            "name":          path.name,
            "path":          str(path),
            "extension":     path.suffix.lower(),
            "size_mb":       round(stat.st_size / 1_048_576, 3),
            "last_accessed": datetime.utcfromtimestamp(stat.st_atime).isoformat(),
            "last_modified": datetime.utcfromtimestamp(stat.st_mtime).isoformat(),
            "is_inactive":   is_inactive,
            "risk_level":    risk_level,
            "risks":         findings,
        }
    except (PermissionError, OSError):
        return None


def walk_drives() -> List[Path]:
    """Retorna os pontos de entrada para varredura conforme o SO."""
    system = platform.system()
    if system == "Windows":
        import string
        return [Path(f"{d}:\\") for d in string.ascii_uppercase if Path(f"{d}:\\").exists()]
    else:
        return [Path("/home"), Path("/var"), Path("/opt"), Path("/srv"), Path("/root")]


def iter_files(roots: List[Path]) -> Generator[Path, None, None]:
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root, topdown=True):
            dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
            for name in filenames:
                yield Path(dirpath) / name


# ─── API Client ──────────────────────────────────────────────────────────────

class SentinelAPIClient:
    def __init__(self, api_url: str, agent_key: str, user_token: str):
        self.api_url    = api_url.rstrip("/")
        self.agent_key  = agent_key
        self.user_token = user_token

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.user_token}",
            "X-Agent-Key":   self.agent_key,
            "Content-Type":  "application/json",
        }

    async def ping(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(f"{self.api_url}/ping")
                return r.status_code == 200
        except Exception:
            return False

    async def start_scan(self, days: int) -> str:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(
                f"{self.api_url}/scans",
                headers=self._headers(),
                params={"days": days},
            )
            r.raise_for_status()
            return r.json()["scan_id"]

    async def send_batch(
        self,
        scan_id: str,
        results: List[dict],
        total_files: int,
        processed_files: int,
        is_complete: bool = False,
    ):
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post(
                f"{self.api_url}/ingest",
                headers=self._headers(),
                json={
                    "scan_id":         scan_id,
                    "results":         results,
                    "total_files":     total_files,
                    "processed_files": processed_files,
                    "is_complete":     is_complete,
                },
            )
            r.raise_for_status()
            return r.json()


# ─── Scan runner ─────────────────────────────────────────────────────────────

async def run_scan(cfg: dict, days: int = 180):
    client = SentinelAPIClient(
        api_url    = cfg["api_url"],
        agent_key  = cfg["agent_key"],
        user_token = cfg["user_token"],
    )

    if not await client.ping():
        log.error("API inacessível. Verifique a URL e a conexão.")
        return

    log.info(f"Iniciando scan (threshold: {days} dias)...")
    scan_id          = await client.start_scan(days)
    threshold_secs   = days * 86400

    roots        = walk_drives()
    batch        = []
    total_files  = 0
    found        = 0
    processed    = 0

    # Contagem prévia (estimativa de progresso)
    log.info("Contando arquivos (estimativa)...")
    total_files = sum(1 for _ in iter_files(roots))
    log.info(f"~{total_files:,} arquivos encontrados.")

    for file_path in iter_files(roots):
        processed += 1
        result = analyze_file(file_path, threshold_secs)
        if result:
            batch.append(result)
            found += 1

        if len(batch) >= BATCH_SIZE:
            await client.send_batch(scan_id, batch, total_files, processed)
            log.info(f"Batch enviado | processados: {processed:,}/{total_files:,} | riscos: {found}")
            batch = []

        # Pequena pausa a cada 10k arquivos para não sobrecarregar
        if processed % 10_000 == 0:
            await asyncio.sleep(0.1)

    # Envia último batch com is_complete=True
    await client.send_batch(scan_id, batch, total_files, processed, is_complete=True)
    log.info(f"✅ Scan concluído! {found} itens relevantes em {processed:,} arquivos.")

    # Atualiza próximo scan agendado
    cfg["last_scan"] = datetime.utcnow().isoformat()
    save_config(cfg)


# ─── Daemon loop ─────────────────────────────────────────────────────────────

async def daemon_loop(cfg: dict):
    log.info("Agente Sentinel360 iniciado em modo daemon.")
    interval = cfg.get("scan_interval", SCAN_INTERVAL)
    days     = cfg.get("days_threshold", 180)

    while True:
        try:
            await run_scan(cfg, days=days)
        except Exception as e:
            log.error(f"Erro no scan: {e}")
        log.info(f"Próximo scan em {interval // 60} minutos.")
        await asyncio.sleep(interval)


# ─── CLI ─────────────────────────────────────────────────────────────────────

def cmd_install(args):
    cfg = {
        "api_url":       args.api_url,
        "agent_key":     args.agent_key,
        "user_token":    args.user_token,
        "days_threshold": args.days,
        "scan_interval": args.interval * 60,
        "hostname":      platform.node(),
        "platform":      platform.system().lower(),
    }
    save_config(cfg)
    log.info("Agente configurado com sucesso!")
    log.info(f"Execute 's360-agent run' para iniciar uma varredura agora.")

def cmd_run(args):
    cfg  = load_config()
    days = args.days or cfg.get("days_threshold", 180)
    asyncio.run(run_scan(cfg, days=days))

def cmd_daemon(args):
    cfg = load_config()
    if not cfg:
        log.error("Execute 's360-agent install' primeiro.")
        sys.exit(1)

    def handle_exit(sig, frame):
        log.info("Daemon encerrado.")
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_exit)
    signal.signal(signal.SIGINT,  handle_exit)
    asyncio.run(daemon_loop(cfg))

def cmd_status(args):
    cfg = load_config()
    if not cfg:
        print("Agente não configurado. Execute: s360-agent install --help")
        return
    print(json.dumps({k: v for k, v in cfg.items() if k != "user_token"}, indent=2))


def main():
    parser = argparse.ArgumentParser(prog="s360-agent", description="Sentinel360 Remote Agent")
    subs   = parser.add_subparsers(dest="command")

    # install
    p_install = subs.add_parser("install", help="Configura o agente")
    p_install.add_argument("--api-url",    required=True, help="URL da API Sentinel360")
    p_install.add_argument("--agent-key",  required=True, help="API key do agente (gerada no dashboard)")
    p_install.add_argument("--user-token", required=True, help="Token JWT do usuário (para iniciar scans)")
    p_install.add_argument("--days",       type=int, default=180, help="Dias para considerar inatividade")
    p_install.add_argument("--interval",   type=int, default=60,  help="Intervalo entre scans (minutos)")
    p_install.set_defaults(func=cmd_install)

    # run
    p_run = subs.add_parser("run", help="Executa um scan imediatamente")
    p_run.add_argument("--days", type=int, help="Dias para inatividade (sobrescreve config)")
    p_run.set_defaults(func=cmd_run)

    # daemon
    p_daemon = subs.add_parser("daemon", help="Roda em loop contínuo")
    p_daemon.set_defaults(func=cmd_daemon)

    # status
    p_status = subs.add_parser("status", help="Exibe configuração atual")
    p_status.set_defaults(func=cmd_status)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
