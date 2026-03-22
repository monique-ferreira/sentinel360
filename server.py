from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import scanner_engine
import database
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://sentinel360-cyber.vercel.app", # Sua URL oficial
        "http://localhost:5173",               # Para testes locais
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

class GlobalState:
    def __init__(self):
        self.is_scanning = False
        self.progress = 0
        self.total_files = 0
        self.processed_files = 0
        self.estimated_remaining = 0
        self.start_time = 0

state = GlobalState()

@app.get("/scan-status")
def get_status():
    return {
        "is_scanning": state.is_scanning,
        "progress": round(state.progress, 1),
        "total": state.total_files,
        "processed": state.processed_files,
        "eta_seconds": state.estimated_remaining
    }

@app.post("/scan")
async def start_scan(background_tasks: BackgroundTasks, days: int = 180):
    if state.is_scanning:
        return {"message": "Já existe um escaneamento em curso."}
    
    state.is_scanning = True
    background_tasks.add_task(run_and_store, days)
    return {"message": "Escaneamento iniciado em segundo plano."}

def run_and_store(days):
    try:
        resultados = scanner_engine.run_full_scan(days, state)
        database.save_scan_results(resultados)
    finally:
        state.is_scanning = False
        state.progress = 100

@app.get("/results")
def get_results():
    return {"items": database.get_all_results()}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)