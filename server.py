import os
import time
import re
import platform
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(title="Sentinel 360 API")

# Habilita CORS para o seu frontend no Vercel
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- LÓGICA DO MOTOR (Engine) ---

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

class ScanState:
    results = []
    is_scanning = False

state = ScanState()

def fast_check_item(path, seconds_threshold):
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
            return {
                "nome": os.path.basename(path),
                "caminho": path,
                "inativo": "SIM" if is_inactive else "NÃO",
                "riscos": ", ".join(risks) if risks else "NENHUM",
                "tamanho_mb": round(stats.st_size / (1024*1024), 3)
            }
    except:
        return None

def run_scan_task(days: int):
    state.is_scanning = True
    state.results = []
    seconds_threshold = days * 24 * 60 * 60
    
    # Define diretório raiz baseado no SO (Render usa Linux /)
    root_dir = "/" if platform.system() != "Windows" else "C:\\"
    
    try:
        with ThreadPoolExecutor(max_workers=20) as executor:
            for root, dirs, files in os.walk(root_dir, topdown=True):
                dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith('.')]
                for name in files:
                    file_path = os.path.join(root, name)
                    res = executor.submit(fast_check_item, file_path, seconds_threshold).result()
                    if res:
                        state.results.append(res)
    finally:
        state.is_scanning = False

# --- ENDPOINTS API ---

@app.get("/")
def health():
    return {"status": "Sentinel 360 Online"}

@app.post("/scan")
async def start_scan(days: int, background_tasks: BackgroundTasks):
    if state.is_scanning:
        raise HTTPException(status_code=400, detail="Varredura já em curso.")
    background_tasks.add_task(run_scan_task, days)
    return {"message": "Varredura iniciada."}

@app.get("/results")
def get_results():
    return {"is_scanning": state.is_scanning, "items": state.results}

@app.delete("/delete-item")
def delete_item(path: str):
    try:
        if os.path.exists(path):
            os.remove(path)
            state.results = [i for i in state.results if i['caminho'] != path]
            return {"message": "Sucesso"}
        raise HTTPException(status_code=404, detail="Arquivo não encontrado")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)