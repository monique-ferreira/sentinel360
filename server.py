import os
import time
import re
import platform
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import uvicorn
import database # Importa o arquivo que criamos acima

# Importe os motores que criamos antes
# Certifique-se que scanner_engine.py e actions_manager.py estão na mesma pasta
import scanner_engine
import actions_manager

app = FastAPI(title="Sentinel 360 API")

# CONFIGURAÇÃO DE SEGURANÇA (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://sentinel360-cyber.vercel.app", # Sua URL oficial
        "http://localhost:5173",               # Para testes locais
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanState:
    results = []
    is_scanning = False

state = ScanState()

@app.get("/")
def health():
    return {"status": "Sentinel 360 Online", "node": platform.node()}

@app.post("/scan")
async def start_scan(days: Optional[int] = 180, background_tasks: BackgroundTasks = None):
    if state.is_scanning:
        raise HTTPException(status_code=400, detail="Varredura já em curso.")
    
    state.is_scanning = True
    background_tasks.add_task(run_and_store, days)
    return {"message": "Varredura iniciada. Os dados serão salvos no MongoDB."}

def run_and_store(days):
    try:
        # 1. Roda o scanner
        resultados = scanner_engine.run_full_scan(days)
        # 2. Salva no MongoDB
        database.save_scan_results(resultados)
    finally:
        state.is_scanning = False

@app.get("/results")
def get_results():
    # Agora busca direto do banco de dados!
    items = database.get_all_results()
    return {
        "is_scanning": state.is_scanning,
        "count": len(items),
        "items": items
    }

@app.delete("/delete-item")
async def delete_item(path: str):
    # Remove do disco (opcional) e do banco de dados
    try:
        if os.path.exists(path):
            os.remove(path)
        database.delete_specific_file(path)
        return {"message": "Arquivo removido com sucesso."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
if __name__ == "__main__":
    # O Render exige que usemos a porta da variável de ambiente PORT
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)