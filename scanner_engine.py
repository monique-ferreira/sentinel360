import os
import time
import re
import platform
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Configurações de filtros e busca
IGNORE_DIRS = {
    'C:\\Windows', 'AppData', 'node_modules', '$Recycle.Bin', 
    'Program Files', 'C:\\ProgramData', 'System Volume Information',
    '.git', '.venv', 'venv', 'site-packages', '__pycache__'
}

TEXT_EXT = {'.txt', '.log', '.conf', '.ini', '.py', '.json', '.sql', '.env', '.xml', '.yaml'}

SENSITIVE_PATTERNS = {
    "Credencial": r"(?i)(password|senha|pwd|secret|admin)[\s:=]+['\"]?([^\s'\"#]+)['\"]?",
    "Token/Key": r"(?i)(api[_-]key|token|auth|access_key)[\s:=]+['\"]([a-zA-Z0-9_\-]{16,})['\"]",
    "CPF/Documento": r"\d{3}\.\d{3}\.\d{3}-\d{2}",
    "Chave Privada": r"-----BEGIN (RSA|OPENSSH|PRIVATE) KEY-----",
}

def fast_check_item(path, seconds_threshold, found_items):
    """Analisa um arquivo individual e o adiciona à lista se houver risco ou inatividade."""
    try:
        stats = os.stat(path)
        is_inactive = (time.time() - stats.st_atime) > seconds_threshold
        
        risks = []
        if os.path.splitext(path)[1].lower() in TEXT_EXT:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(8192) 
                for label, pattern in SENSITIVE_PATTERNS.items():
                    if re.search(pattern, content):
                        risks.append(label)

        if is_inactive or risks:
            found_items.append({
                "nome": os.path.basename(path),
                "caminho": path,
                "inativo": "SIM" if is_inactive else "NÃO",
                "riscos": ", ".join(risks) if risks else "NENHUM",
                "tamanho_mb": round(stats.st_size / (1024*1024), 3)
            })
    except:
        pass

def run_full_scan(days_limit):
    """Coordena a varredura multi-thread em todas as unidades."""
    seconds_threshold = days_limit * 24 * 60 * 60
    found_items = []
    
    drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")] if platform.system() == "Windows" else ["/"]

    with ThreadPoolExecutor(max_workers=32) as executor:
        for drive in drives:
            for root, dirs, files in os.walk(drive, topdown=True):
                # Poda de pastas irrelevantes
                dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith('.')]
                
                for name in files:
                    file_path = os.path.join(root, name)
                    executor.submit(fast_check_item, file_path, seconds_threshold, found_items)
    
    return found_items