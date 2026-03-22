import os
import time
from typing import Optional
from fastapi import FastAPI, BackgroundTasks, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

# Meus módulos internos
import scanner_engine
import database
import auth_manager # Para gerar tokens e hash de senha

app = FastAPI(title="Sentinel 360 API")

# Configuração de CORS para aceitar o seu Frontend (Vercel ou Local)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- MODELOS DE DADOS ---

class UserAuth(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    fullname: Optional[str] = None

class ScanState:
    def __init__(self):
        self.is_scanning = False
        self.progress = 0
        self.total_files = 0
        self.processed_files = 0
        self.eta_seconds = 0
        self.start_time = 0

state = ScanState()

# --- ENDPOINTS DE AUTENTICAÇÃO ---

@app.post("/register")
async def register(user: UserAuth):
    # Verifica se usuário já existe
    existing_user = database.db["users"].find_one({"username": user.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Usuário já cadastrado.")
    
    # Cria o hash da senha por segurança
    hashed_password = auth_manager.get_password_hash(user.password)
    
    user_data = {
        "username": user.username,
        "password": hashed_password,
        "email": user.email,
        "fullname": user.fullname,
        "created_at": time.time()
    }
    
    database.db["users"].insert_one(user_data)
    return {"message": "Usuário registrado com sucesso!"}

@app.post("/login")
async def login(user: UserAuth):
    db_user = database.db["users"].find_one({"username": user.username})
    
    if not db_user or not auth_manager.verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Credenciais inválidas.")
    
    # Gera o token JWT real
    access_token = auth_manager.create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# --- ENDPOINTS DO SCANNER ---

@app.get("/scan-status")
def get_scan_status():
    return {
        "is_scanning": state.is_scanning,
        "progress": round(state.progress, 1),
        "total": state.total_files,
        "processed": state.processed_files,
        "eta_seconds": state.eta_seconds
    }

@app.post("/scan")
async def start_scan(background_tasks: BackgroundTasks, days: int = 180):
    if state.is_scanning:
        return {"message": "Varredura já em curso."}
    
    state.is_scanning = True
    state.progress = 0
    background_tasks.add_task(run_and_store, days)
    return {"message": "Motor Sentinel iniciado."}

def run_and_store(days):
    try:
        # O scanner_engine agora recebe o objeto 'state' para atualizar o progresso
        resultados = scanner_engine.run_full_scan(days, state)
        database.save_scan_results(resultados)
    finally:
        state.is_scanning = False
        state.progress = 100

@app.get("/results")
def get_results():
    items = database.get_all_results()
    return {"items": items}

@app.delete("/delete-item")
async def delete_item(path: str):
    success = database.delete_specific_file(path)
    if success:
        # Tenta deletar do disco se estiver rodando local
        if os.path.exists(path):
            try: os.remove(path)
            except: pass
        return {"message": "Item removido com sucesso."}
    raise HTTPException(status_code=404, detail="Item não encontrado no banco.")

@app.get("/ping")
async def ping():
    return {"status": "alive", "timestamp": time.time()}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)