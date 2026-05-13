import os
import time
from typing import Optional
from fastapi import FastAPI, BackgroundTasks, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

# Meus mÃÂ³dulos internos
import scanner_engine
import database
import auth_manager # Para gerar tokens e hash de senha

app = FastAPI(title="Sentinel 360 API")

# ConfiguraÃÂ§ÃÂ£o de CORS para aceitar o seu Frontend (Vercel ou Local)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",  # Frontend local
        "https://sentinel360-cyber.vercel.app"  # Frontend Vercel
    ],
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

# --- ENDPOINTS DE AUTENTICAÃÂÃÂO ---

@app.post("/register")
async def register(user: UserAuth):
    # Verifica se usuÃÂ¡rio jÃÂ¡ existe
    existing_user = database.db["users"].find_one({"username": user.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="UsuÃÂ¡rio jÃÂ¡ cadastrado.")
    
    # Cria o hash da senha por seguranÃÂ§a
    hashed_password = auth_manager.get_password_hash(user.password)
    
    user_data = {
        "username": user.username,
        "password": hashed_password,
        "email": user.email,
        "fullname": user.fullname,
        "created_at": time.time()
    }
    
    database.db["users"].insert_one(user_data)
    return {"message": "UsuÃÂ¡rio registrado com sucesso!"}

@app.post("/login")
async def login(user: UserAuth):
    # Aceita login por username OU email
    db_user = database.db["users"].find_one({"username": user.username})
    if not db_user:
        db_user = database.db["users"].find_one({"email": user.username})
    
    if not db_user or not auth_manager.verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Credenciais invÃ¡lidas.")
    
    # Gera o token JWT real
    access_token = auth_manager.create_access_token(data={"sub": db_user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

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
        return {"message": "Varredura jÃÂ¡ em curso."}
    
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
    raise HTTPException(status_code=404, detail="Item nÃÂ£o encontrado no banco.")

@app.get("/ping")
async def ping():
    return {"status": "alive", "timestamp": time.time()}


# ── Microsoft 365 Integration ──

_ms365_config = {}

class MS365ConfigRequest(BaseModel):
    tenant_id: str
    client_id: str
    client_secret: str

@app.post("/integrations/office365/configure")
async def configure_office365(body: MS365ConfigRequest):
    _ms365_config["tenant_id"] = body.tenant_id
    _ms365_config["client_id"] = body.client_id
    _ms365_config["client_secret"] = body.client_secret
    return {"message": "Credenciais do Office 365 salvas com sucesso."}

@app.get("/integrations/office365/audit")
async def audit_office365(inactive_days: int = 90):
    if not _ms365_config.get("tenant_id"):
        raise HTTPException(status_code=400, detail="Office 365 nao configurado. Salve as credenciais primeiro.")
    try:
        import httpx
        # Get access token
        token_url = f"https://login.microsoftonline.com/{_ms365_config['tenant_id']}/oauth2/v2.0/token"
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(token_url, data={
                "grant_type": "client_credentials",
                "client_id": _ms365_config["client_id"],
                "client_secret": _ms365_config["client_secret"],
                "scope": "https://graph.microsoft.com/.default",
            })
            resp.raise_for_status()
            access_token = resp.json()["access_token"]

        # Get users
        from datetime import datetime, timedelta
        threshold = (datetime.utcnow() - timedelta(days=inactive_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(
                "https://graph.microsoft.com/v1.0/users",
                headers={"Authorization": f"Bearer {access_token}"},
                params={
                    "$select": "id,displayName,userPrincipalName,signInActivity,accountEnabled",
                    "$filter": "accountEnabled eq true",
                    "$top": "999",
                }
            )
            resp.raise_for_status()
            users = resp.json().get("value", [])

        inactive = []
        for u in users:
            sign_in = u.get("signInActivity") or {}
            last = sign_in.get("lastSignInDateTime")
            if not last or last < threshold:
                try:
                    days_diff = (datetime.utcnow() - datetime.fromisoformat(last.replace("Z", "+00:00")).replace(tzinfo=None)).days if last else -1
                except Exception:
                    days_diff = -1
                inactive.append({
                    "id": u["id"],
                    "display_name": u.get("displayName", ""),
                    "email": u.get("userPrincipalName", ""),
                    "last_signin": last,
                    "days_inactive": days_diff,
                })
        return {
            "total_users": len(users),
            "inactive_users": inactive,
            "inactive_count": len(inactive),
            "inactive_threshold": inactive_days,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao consultar Office 365: {str(e)}")

@app.get("/integrations/office365/users")
async def list_office365_users():
    return await audit_office365(inactive_days=9999)

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)