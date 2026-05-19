"""
scanner_engine.py — Motor de varredura multiplataforma do Sentinel360

Suporta Windows (drives A-Z) e Linux/macOS (sistema de arquivos raiz).
Detecta arquivos inativos e conteúdo sensível com padrões abrangentes.
"""

import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Configuração ───────────────────────────────────────────────────────────────

MAX_WORKERS = min(16, (os.cpu_count() or 4) * 2)
READ_BYTES   = 8192   # bytes lidos de cada arquivo de texto

IGNORE_DIRS = {
    # Windows
    "Windows", "Program Files", "Program Files (x86)", "ProgramData",
    "AppData", "$Recycle.Bin", "$WinREAgent", "System Volume Information",
    "Recovery", "PerfLogs",
    # Linux / macOS
    "proc", "sys", "dev", "run", "tmp", "boot",
    "lost+found", ".git", "__pycache__",
    # Dev / build
    "node_modules", ".npm", ".yarn", "dist", "build", ".venv", "venv",
    ".cache", ".local",
}

TEXT_EXT = {
    ".txt", ".log", ".conf", ".cfg", ".ini", ".py", ".js", ".ts",
    ".json", ".sql", ".env", ".xml", ".yaml", ".yml", ".toml",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".csv", ".md", ".html", ".htm", ".php", ".rb", ".go",
    ".properties", ".credentials", ".secret",
}

# Padrões sensíveis — chave: label exibida no frontend
SENSITIVE_PATTERNS: dict[str, str] = {
    # Credenciais genéricas
    "Credencial": (
        r"(?i)(password|passwd|senha|pwd|secret|api_key|apikey|access_key|token)"
        r"\s*[=:\"']+\s*[^\s\"']{6,}"
    ),
    # Chaves privadas
    "Chave Privada": (
        r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP|PRIVATE)\s+KEY(?: BLOCK)?-----"
    ),
    # Tokens de serviços cloud e plataformas
    "Token/Key": (
        r"(?:"
        r"AKIA[0-9A-Z]{16}"                        # AWS Access Key ID
        r"|(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}"  # GitHub tokens
        r"|sk-[A-Za-z0-9]{20,}"                    # OpenAI / Stripe keys
        r"|xoxb-[0-9A-Za-z\-]+"                    # Slack bot token
        r"|AIza[0-9A-Za-z\-_]{35}"                 # Google API key
        r"|[0-9a-f]{32,64}(?=\s|$|[\"'])"          # Hashes/tokens genéricos longos
        r")"
    ),
    # Dados pessoais brasileiros
    "CPF": r"\b\d{3}[.\-]?\d{3}[.\-]?\d{3}[-]?\d{2}\b",
    "CNPJ": r"\b\d{2}[.\-]?\d{3}[.\-]?\d{3}[\/]?\d{4}[-]?\d{2}\b",
    # Emails expostos em arquivos de configuração
    "Email": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    # Strings de conexão de banco de dados
    "Connection String": (
        r"(?i)(mongodb(\+srv)?://|mysql://|postgres(ql)?://|mssql://)"
        r"[^\s\"'<>]+"
    ),
}

# Nomes de arquivo que por si só indicam risco (independente do conteúdo)
SENSITIVE_FILENAMES = re.compile(
    r"(?i)(password|passwd|credentials|secrets?|private[_\-]?key"
    r"|\.env|id_rsa|id_dsa|id_ecdsa|id_ed25519|\.pem|\.p12|\.pfx"
    r"|htpasswd|shadow|\.aws[/\\]credentials|config\.ini)",
    re.IGNORECASE,
)


# ── Utilitários ────────────────────────────────────────────────────────────────

def _get_scan_roots() -> list[str]:
    """Retorna raízes de varredura de acordo com o SO."""
    if sys.platform.startswith("win"):
        return [
            f"{d}:\\"
            for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            if os.path.exists(f"{d}:\\")
        ]
    else:
        # Linux / macOS: diretórios de usuário + dados corporativos
        candidates = ["/home", "/opt", "/srv", "/var/www", "/data",
                      os.path.expanduser("~")]
        return [p for p in candidates if os.path.isdir(p)]


def _should_skip(dirname: str) -> bool:
    return dirname in IGNORE_DIRS or dirname.startswith(".")


def _count_files(roots: list[str]) -> int:
    total = 0
    for root in roots:
        for _, dirs, files in os.walk(root, topdown=True):
            dirs[:] = [d for d in dirs if not _should_skip(d)]
            total += len(files)
    return total


# ── Análise de arquivo individual ─────────────────────────────────────────────

def check_file(file_path: str, threshold_seconds: float) -> dict | None:
    """
    Analisa um único arquivo.
    Retorna dict com metadados e riscos, ou None se não for relevante.
    """
    try:
        stats = os.stat(file_path)
    except OSError:
        return None

    is_inactive = (time.time() - stats.st_atime) > threshold_seconds
    risks: list[str] = []
    filename = os.path.basename(file_path)

    # Detecção pelo nome do arquivo
    if SENSITIVE_FILENAMES.search(filename) or SENSITIVE_FILENAMES.search(file_path):
        risks.append("Credencial")  # nome suspeito = credencial potencial

    # Detecção pelo conteúdo (apenas extensões de texto)
    ext = os.path.splitext(filename)[1].lower()
    if ext in TEXT_EXT and stats.st_size > 0:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(READ_BYTES)
            for label, pattern in SENSITIVE_PATTERNS.items():
                if re.search(pattern, content):
                    if label not in risks:
                        risks.append(label)
        except OSError:
            pass

    # Só inclui se inativo OU tiver risco
    if not is_inactive and not risks:
        return None

    return {
        "nome":       filename,
        "caminho":    file_path,
        "inativo":    "SIM" if is_inactive else "NÃO",
        "riscos":     ", ".join(risks) if risks else "NENHUM",
        "tamanho_mb": round(stats.st_size / (1024 * 1024), 3),
    }


# ── Orquestrador principal ─────────────────────────────────────────────────────

def run_full_scan(days_threshold: int, state_ref) -> list[dict]:
    """
    Executa varredura completa e atualiza state_ref com progresso.

    Args:
        days_threshold: Arquivos com último acesso > N dias são marcados inativos.
        state_ref: Objeto ScanState com atributos:
                   is_scanning, progress, total_files, processed_files, eta_seconds.
    Returns:
        Lista de dicts com arquivos detectados.
    """
    roots = _get_scan_roots()
    threshold_seconds = days_threshold * 86_400

    print(f"[SCAN] Contando arquivos em: {roots}")
    state_ref.total_files = _count_files(roots)
    state_ref.processed_files = 0
    state_ref.start_time = time.time()
    print(f"[SCAN] Total a varrer: {state_ref.total_files} arquivos")

    results: list[dict] = []

    def _collect(file_path: str):
        nonlocal results
        item = check_file(file_path, threshold_seconds)
        if item:
            results.append(item)
        state_ref.processed_files += 1
        if state_ref.total_files > 0:
            state_ref.progress = (state_ref.processed_files / state_ref.total_files) * 100
        elapsed = time.time() - state_ref.start_time
        if state_ref.processed_files > 0:
            avg = elapsed / state_ref.processed_files
            remaining = state_ref.total_files - state_ref.processed_files
            state_ref.eta_seconds = round(avg * remaining)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for root in roots:
            for dirpath, dirs, files in os.walk(root, topdown=True):
                dirs[:] = [d for d in dirs if not _should_skip(d)]
                for name in files:
                    fp = os.path.join(dirpath, name)
                    futures.append(executor.submit(_collect, fp))

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"[SCAN] Erro em arquivo: {e}")

    print(f"[SCAN] Concluído. {len(results)} itens encontrados.")
    return results
