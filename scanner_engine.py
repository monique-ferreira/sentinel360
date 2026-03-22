import os
import time
import re
from concurrent.futures import ThreadPoolExecutor

# Configurações de Escaneamento
IGNORE_DIRS = {'C:\\Windows', 'AppData', 'node_modules', '$Recycle.Bin', 'Program Files', 'C:\\ProgramData'}
TEXT_EXT = {'.txt', '.log', '.conf', '.ini', '.py', '.json', '.sql', '.env', '.xml', '.yaml'}
SENSITIVE_PATTERNS = {
    "Credencial": r"(?i)(password|senha|pwd|secret|admin)[\s:=]+([^\s\"']+)",
    "CPF": r"\d{3}\.\d{3}\.\d{3}-\d{2}",
    "Chave Privada": r"-----BEGIN (RSA|OPENSSH|PRIVATE) KEY-----",
}

def count_total_files(drives):
    """Faz uma contagem rápida de quantos arquivos existem no total para a porcentagem."""
    total = 0
    for drive in drives:
        for root, dirs, files in os.walk(drive, topdown=True):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            total += len(files)
    return total

def check_file(file_path, threshold_seconds):
    try:
        stats = os.stat(file_path)
        is_inactive = (time.time() - stats.st_atime) > threshold_seconds
        risks = []
        
        if os.path.splitext(file_path)[1].lower() in TEXT_EXT:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(4096)
                for label, pattern in SENSITIVE_PATTERNS.items():
                    if re.search(pattern, content):
                        risks.append(label)
        
        if is_inactive or risks:
            return {
                "nome": os.path.basename(file_path),
                "caminho": file_path,
                "inativo": "SIM" if is_inactive else "NÃO",
                "riscos": ", ".join(risks) if risks else "NENHUM",
                "tamanho_mb": round(stats.st_size / (1024*1024), 2)
            }
    except:
        return None

def run_full_scan(days_threshold, state_ref):
    drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
    
    # Início do processo
    state_ref.total_files = count_total_files(drives)
    state_ref.processed_files = 0
    state_ref.start_time = time.time()
    
    resultados = []
    threshold_seconds = days_threshold * 24 * 60 * 60

    with ThreadPoolExecutor(max_workers=10) as executor:
        for drive in drives:
            for root, dirs, files in os.walk(drive, topdown=True):
                dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
                for name in files:
                    file_path = os.path.join(root, name)
                    
                    # Processa o arquivo
                    res = check_file(file_path, threshold_seconds)
                    if res:
                        resultados.append(res)
                    
                    # Atualiza o progresso global
                    state_ref.processed_files += 1
                    state_ref.progress = (state_ref.processed_files / state_ref.total_files) * 100
                    
                    # Cálculo de Tempo Estimado (ETA)
                    elapsed = time.time() - state_ref.start_time
                    if state_ref.processed_files > 0:
                        avg_time_per_file = elapsed / state_ref.processed_files
                        remaining_files = state_ref.total_files - state_ref.processed_files
                        state_ref.estimated_remaining = round(avg_time_per_file * remaining_files)

    return resultados