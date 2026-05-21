"""
server.py — API FastAPI do Sentinel360

Endpoints:
  Auth:        POST /register  POST /login  POST /forgot-password
  Profile:     GET /user/me  PUT /user/me  GET /user/settings  PUT /user/settings
  Orgs:        GET /orgs/search  POST /orgs/create  POST /orgs/join
               GET /orgs/my/requests  POST /orgs/my/requests/{username}/approve
               POST /orgs/my/requests/{username}/reject  GET /orgs/my/members
  Workspace:   GET /workspace
  Results:     GET /results  DELETE /delete-item  GET /export/csv
  Integrations:
    POST /integrations/office365/configure   GET /integrations/office365/audit
    POST /integrations/office365/scan-files  GET /integrations/office365/file-results
    POST /integrations/azure/configure       GET /integrations/azure/audit
    POST /integrations/azure/scan-files      GET /integrations/azure/file-results
    POST /integrations/personal/scan-files   GET /integrations/personal/file-results
    GET  /integrations/office365/scan-status
  OAuth MS:    GET /auth/microsoft/login  POST /auth/microsoft/exchange
               GET /auth/microsoft/callback  GET /auth/microsoft/status
  Report:      GET /report/bi
  Health:      GET /ping
"""

import csv
import io
import os
import threading
import time
import urllib.parse
from typing import Optional

import requests as req
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from pydantic import BaseModel

import auth_manager
import database
import ms_graph
import bi_report
import bi_excel

# ── OAuth Microsoft (delegated) ───────────────────────────────────────────────

MS_CLIENT_ID     = os.environ.get("MS_CLIENT_ID", "")
MS_CLIENT_SECRET = os.environ.get("MS_CLIENT_SECRET", "")
MS_REDIRECT_URI  = os.environ.get("MS_REDIRECT_URI", "https://sentinel360-cyber.vercel.app/integrations")
MS_SCOPES        = "Files.ReadWrite Sites.ReadWrite.All User.Read offline_access"
FRONTEND_URL     = os.environ.get("FRONTEND_URL", "https://sentinel360-cyber.vercel.app")

# ── App & CORS ────────────────────────────────────────────────────────────────

app = FastAPI(title="Sentinel360 API", version="2.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://sentinel360-cyber.vercel.app",
        "http://localhost:5173",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Modelos ───────────────────────────────────────────────────────────────────

class RegisterBody(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    account_type: Optional[str] = "personal"  # "personal" | "corporate"
    org_name: Optional[str] = None
    org_slug: Optional[str] = None
    org_action: Optional[str] = None  # "create" | "join"
    org_id: Optional[str] = None      # for joining existing org


class UpdateProfileBody(BaseModel):
    full_name: Optional[str] = None
    email: Optional[str] = None
    inactivity_days: Optional[int] = None


class UserSettingsBody(BaseModel):
    inactivity_days: int


class CreateOrgBody(BaseModel):
    name: str
    slug: str


class JoinOrgBody(BaseModel):
    org_id: str


class LoginBody(BaseModel):
    username: str
    password: str


class ForgotPasswordBody(BaseModel):
    email: str


class IntegrationConfigBody(BaseModel):
    tenant_id: str
    client_id: str
    client_secret: str


class MsExchangeBody(BaseModel):
    code: str
    state: str = ""


# ── Estado de varredura por usuário ───────────────────────────────────────────

class CloudScanState:
    def __init__(self):
        self.is_scanning     = False
        self.progress        = 0.0
        self.provider        = ""
        self.error           = ""
        self.processed_files = 0
        self.start_time      = 0.0
        self.eta_seconds     = -1

    def start(self, provider: str):
        self.is_scanning     = True
        self.progress        = 0.0
        self.provider        = provider
        self.error           = ""
        self.processed_files = 0
        self.start_time      = time.time()
        self.eta_seconds     = -1

    def on_file(self, count: int):
        self.processed_files = count
        elapsed = time.time() - self.start_time
        if elapsed > 0 and count > 0:
            rate = count / elapsed           # files/sec
            # Soft progress: asymptotic toward 99% so it never snaps to 100 prematurely
            self.progress = min(99.0, round(100 * (1 - 1 / (1 + count / 50)), 1))
            self.eta_seconds = int(count / rate)  # time already spent = rough remaining estimate

    def finish(self):
        self.is_scanning = False
        self.progress    = 100.0
        self.eta_seconds = 0


_scan_states: dict[str, CloudScanState] = {}


def _get_scan_state(username: str) -> CloudScanState:
    if username not in _scan_states:
        _scan_states[username] = CloudScanState()
    return _scan_states[username]


# ── Autenticação via JWT ──────────────────────────────────────────────────────

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


async def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token inválido ou expirado.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = auth_manager.decode_token(token)
        username: str = payload.get("sub")
        if not username:
            raise credentials_exc
    except JWTError:
        raise credentials_exc

    user = database.find_user(username)
    if user is None:
        raise credentials_exc
    return username


# ── Helper: restrict corporate members ───────────────────────────────────────

def require_not_restricted(username: str):
    s = database.get_user_settings(username)
    if s.get("account_type") == "corporate" and s.get("org_role") != "admin" and s.get("org_status") == "approved":
        raise HTTPException(status_code=403, detail="Acesso restrito para membros corporativos. Solicite acesso ao administrador.")


# ── Endpoints de autenticação ─────────────────────────────────────────────────

@app.post("/register", status_code=201)
async def register(body: RegisterBody):
    import uuid as _uuid
    if database.find_user(body.username):
        raise HTTPException(status_code=409, detail="Usuário já cadastrado.")
    if body.email and database.find_user_by_email(body.email):
        raise HTTPException(status_code=409, detail="Email já cadastrado.")

    account_type = body.account_type or "personal"
    user_doc: dict = {
        "username":        body.username,
        "password":        auth_manager.get_password_hash(body.password),
        "email":           body.email,
        "full_name":       body.full_name,
        "account_type":    account_type,
        "inactivity_days": 180,
        "created_at":      time.time(),
    }

    if account_type == "corporate":
        if body.org_action == "create" and body.org_name:
            org_id   = str(_uuid.uuid4())
            org_slug = (body.org_slug or body.org_name.lower().replace(" ", "-")).replace(" ", "-")
            database.create_org(org_id, body.org_name, org_slug, body.username)
            user_doc.update({"org_id": org_id, "org_role": "admin", "org_status": "approved"})
        elif body.org_action == "join" and body.org_id:
            org = database.get_org_by_id(body.org_id)
            if not org:
                raise HTTPException(status_code=404, detail="Organização não encontrada.")
            database.create_join_request(body.org_id, body.username)
            user_doc.update({"org_id": body.org_id, "org_role": "member", "org_status": "pending"})

    database.create_user(user_doc)
    database.log_action("REGISTRO", f"Novo usuário: {body.username} ({account_type})", owner=body.username)
    return {"message": "Conta criada com sucesso."}


# ── User profile & settings ───────────────────────────────────────────────────

@app.get("/user/me")
async def get_me(username: str = Depends(get_current_user)):
    settings = database.get_user_settings(username)
    org_name = None
    org_member_count = None
    if settings.get("org_id"):
        org = database.get_org_by_id(settings["org_id"])
        if org:
            org_name = org.get("name")
            if settings.get("org_role") == "admin":
                org_member_count = len(database.get_org_members(settings["org_id"]))
    return {
        "username":        username,
        "full_name":       settings.get("full_name"),
        "email":           settings.get("email"),
        "account_type":    settings.get("account_type", "personal"),
        "org_id":          settings.get("org_id"),
        "org_role":        settings.get("org_role"),
        "org_status":      settings.get("org_status"),
        "org_name":        org_name,
        "org_member_count": org_member_count,
        "inactivity_days": settings.get("inactivity_days", 180),
        "is_restricted": (
            settings.get("account_type") == "corporate"
            and settings.get("org_role") != "admin"
            and settings.get("org_status") == "approved"
        ),
    }


@app.put("/user/me")
async def update_me(body: UpdateProfileBody, username: str = Depends(get_current_user)):
    updates = {k: v for k, v in body.dict().items() if v is not None}
    if body.email and body.email != database.get_user_settings(username).get("email"):
        if database.find_user_by_email(body.email):
            raise HTTPException(status_code=409, detail="Email já em uso.")
    database.update_user_settings(username, updates)
    return {"message": "Perfil atualizado."}


@app.get("/user/settings")
async def get_user_settings_ep(username: str = Depends(get_current_user)):
    s = database.get_user_settings(username)
    return {"inactivity_days": s.get("inactivity_days", 180)}


@app.put("/user/settings")
async def put_user_settings(body: UserSettingsBody, username: str = Depends(get_current_user)):
    database.update_user_settings(username, {"inactivity_days": body.inactivity_days})
    return {"message": "Configurações salvas.", "inactivity_days": body.inactivity_days}


# ── Orgs ──────────────────────────────────────────────────────────────────────

@app.get("/orgs/search")
async def orgs_search(q: str = ""):
    """Public endpoint — used during registration autocomplete (no auth required)."""
    if not q.strip():
        return {"orgs": []}
    return {"orgs": database.search_orgs(q.strip())}


@app.post("/orgs/create", status_code=201)
async def orgs_create(body: CreateOrgBody, username: str = Depends(get_current_user)):
    import uuid as _uuid
    org_id = str(_uuid.uuid4())
    database.create_org(org_id, body.name, body.slug, username)
    database._col("users").update_one(
        {"username": username},
        {"$set": {"org_id": org_id, "org_role": "admin", "org_status": "approved",
                  "account_type": "corporate"}}
    )
    database.log_action("CREATE_ORG", f"Org criada: {body.name}", owner=username)
    return {"message": "Organização criada.", "org_id": org_id}


@app.post("/orgs/join")
async def orgs_join(body: JoinOrgBody, username: str = Depends(get_current_user)):
    org = database.get_org_by_id(body.org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organização não encontrada.")
    database.create_join_request(body.org_id, username)
    database._col("users").update_one(
        {"username": username},
        {"$set": {"org_id": body.org_id, "org_role": "member", "org_status": "pending",
                  "account_type": "corporate"}}
    )
    database.log_action("JOIN_ORG", f"Solicitação para: {org['name']}", owner=username)
    return {"message": "Solicitação enviada. Aguardando aprovação."}


@app.get("/orgs/my/requests")
async def orgs_my_requests(username: str = Depends(get_current_user)):
    settings = database.get_user_settings(username)
    if settings.get("org_role") != "admin":
        raise HTTPException(status_code=403, detail="Apenas administradores podem ver solicitações.")
    requests = database.get_join_requests(settings["org_id"], "pending")
    return {"requests": requests}


@app.post("/orgs/my/requests/{req_username}/approve")
async def orgs_approve(req_username: str, username: str = Depends(get_current_user)):
    settings = database.get_user_settings(username)
    if settings.get("org_role") != "admin":
        raise HTTPException(status_code=403, detail="Apenas administradores podem aprovar.")
    database.update_join_request(settings["org_id"], req_username, "approved")
    database.log_action("APPROVE_MEMBER", f"Aprovado: {req_username}", owner=username)
    return {"message": f"{req_username} aprovado."}


@app.post("/orgs/my/requests/{req_username}/reject")
async def orgs_reject(req_username: str, username: str = Depends(get_current_user)):
    settings = database.get_user_settings(username)
    if settings.get("org_role") != "admin":
        raise HTTPException(status_code=403, detail="Apenas administradores podem rejeitar.")
    database.update_join_request(settings["org_id"], req_username, "rejected")
    database.log_action("REJECT_MEMBER", f"Rejeitado: {req_username}", owner=username)
    return {"message": f"{req_username} rejeitado."}


@app.get("/orgs/my/members")
async def orgs_my_members(username: str = Depends(get_current_user)):
    settings = database.get_user_settings(username)
    if settings.get("org_role") != "admin":
        raise HTTPException(status_code=403, detail="Apenas administradores.")
    members = database.get_org_members(settings["org_id"])
    return {"members": members}


@app.get("/workspace")
async def get_workspace(username: str = Depends(get_current_user)):
    settings = database.get_user_settings(username)
    if settings.get("org_role") != "admin":
        raise HTTPException(status_code=403, detail="Apenas administradores.")
    data = database.get_workspace_data(settings["org_id"])
    return data


@app.post("/orgs/members/{target_username}/promote")
async def promote_to_admin(target_username: str, username: str = Depends(get_current_user)):
    settings = database.get_user_settings(username)
    if settings.get("org_role") != "admin" or settings.get("account_type") != "corporate":
        raise HTTPException(status_code=403, detail="Apenas administradores podem promover membros.")
    target = database.get_user_settings(target_username)
    if target.get("org_id") != settings.get("org_id"):
        raise HTTPException(status_code=404, detail="Membro não encontrado na organização.")
    database.update_user_settings(target_username, {"org_role": "admin"})
    database.log_action("PROMOTE_ADMIN", f"{target_username} promovido a admin", owner=username)
    return {"message": f"{target_username} agora é administrador."}


@app.get("/workspace/member/{target_username}/results")
async def workspace_member_results(target_username: str, username: str = Depends(get_current_user)):
    settings = database.get_user_settings(username)
    if settings.get("org_role") != "admin":
        raise HTTPException(status_code=403, detail="Apenas administradores.")
    target = database.get_user_settings(target_username)
    if target.get("org_id") != settings.get("org_id"):
        raise HTTPException(status_code=404, detail="Membro não encontrado na organização.")
    return {"items": database.get_cloud_results(owner=target_username)}


@app.post("/workspace/member/{target_username}/scan")
async def workspace_member_scan(target_username: str, username: str = Depends(get_current_user)):
    settings = database.get_user_settings(username)
    if settings.get("org_role") != "admin":
        raise HTTPException(status_code=403, detail="Apenas administradores.")
    target_settings = database.get_user_settings(target_username)
    if target_settings.get("org_id") != settings.get("org_id"):
        raise HTTPException(status_code=404, detail="Membro não encontrado na organização.")

    cfg = database.get_integration_config(username, "ms365")
    if not cfg:
        raise HTTPException(status_code=400, detail="Configure as credenciais MS365 da organização primeiro.")

    inactivity_days = target_settings.get("inactivity_days", 180)

    def _run():
        try:
            results = ms_graph.scan_sharepoint_files(
                cfg["tenant_id"], cfg["client_id"], cfg["client_secret"],
                days_threshold=inactivity_days,
            )
            target_email = target_settings.get("email", "").lower()
            if target_email:
                filtered = [r for r in results if target_email in (r.get("origem", "") + r.get("caminho", "")).lower()]
                if filtered:
                    results = filtered
            database.save_cloud_results(target_username, "ms365", results)
            database.log_action("ADMIN_SCAN", f"Scan de {target_username} por admin {username}", owner=username)
        except Exception as e:
            print(f"[WORKSPACE SCAN] Erro: {e}")

    threading.Thread(target=_run, daemon=True).start()
    return {"message": f"Scan iniciado para {target_username}."}


@app.get("/workspace/bi-report")
async def workspace_bi_report(username: str = Depends(get_current_user), target_username: str = ""):
    settings = database.get_user_settings(username)
    if settings.get("org_role") != "admin":
        raise HTTPException(status_code=403, detail="Apenas administradores.")

    if target_username:
        target = database.get_user_settings(target_username)
        if target.get("org_id") != settings.get("org_id"):
            raise HTTPException(status_code=404, detail="Membro não encontrado na organização.")
        items = database.get_cloud_results(owner=target_username)
        label = target_username
    else:
        members = database.get_org_members(settings["org_id"])
        items = []
        for m in members:
            items.extend(database.get_cloud_results(owner=m))
        label = "geral"

    history = database.get_scan_history(owner=target_username if target_username else username)
    xlsx_bytes = bi_excel.generate(items, history)
    filename = f"sentinel360_bi_{label}_{int(time.time())}.xlsx"
    return StreamingResponse(
        iter([xlsx_bytes]),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/login")
async def login(body: LoginBody):
    user = database.find_user(body.username)
    if not user or not auth_manager.verify_password(body.password, user["password"]):
        raise HTTPException(status_code=401, detail="Usuário ou senha incorretos.")

    token = auth_manager.create_access_token({"sub": body.username})
    database.log_action("LOGIN", f"Usuário autenticado: {body.username}", owner=body.username)
    return {"access_token": token, "token_type": "bearer"}


@app.post("/forgot-password")
async def forgot_password(body: ForgotPasswordBody):
    user = database.find_user_by_email(body.email)
    if user:
        database.log_action("RECUPERAÇÃO_SENHA", f"Solicitação para: {body.email}")
    return {"message": "Se o email existir no sistema, você receberá instruções em breve."}


# ── Resultados ────────────────────────────────────────────────────────────────

@app.get("/results")
def get_results(username: str = Depends(get_current_user)):
    require_not_restricted(username)
    return {"items": database.get_cloud_results(owner=username)}


@app.delete("/delete-item")
async def delete_item(
    path: str,
    from_cloud: bool = False,
    username: str = Depends(get_current_user),
):
    """Remove item dos resultados do Sentinel e, opcionalmente, do OneDrive/SharePoint."""
    # Find the item in DB to get graph IDs
    if from_cloud:
        all_items = database.get_cloud_results(owner=username)
        item = next((i for i in all_items if (i.get("caminho") or i.get("Caminho") or i.get("path")) == path), None)
        if not item:
            raise HTTPException(status_code=404, detail="Item não encontrado nos resultados.")
        drive_id = item.get("graph_drive_id", "")
        item_id  = item.get("graph_item_id", "")
        if not drive_id or not item_id:
            raise HTTPException(status_code=422, detail="IDs do OneDrive não disponíveis para este item. Refaça o scan para obter os IDs.")

        # Get access token (personal delegated or corporate app token)
        cfg = database.get_integration_config(username, "ms_personal")
        if cfg and cfg.get("access_token"):
            access_token = cfg["access_token"]
        else:
            # Try corporate MS365 credentials
            cfg365 = database.get_integration_config(username, "ms365")
            if not cfg365:
                raise HTTPException(status_code=400, detail="Nenhuma conta Microsoft conectada.")
            access_token = ms_graph._get_token(
                cfg365["tenant_id"], cfg365["client_id"], cfg365["client_secret"]
            )
        try:
            ms_graph.delete_drive_item(access_token, drive_id, item_id)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Falha ao deletar no OneDrive: {e}")

    database.delete_cloud_result(owner=username, caminho=path)
    return {"deleted": True}


@app.get("/export/csv")
def export_csv(username: str = Depends(get_current_user)):
    require_not_restricted(username)
    items = database.get_cloud_results(owner=username)
    if not items:
        raise HTTPException(status_code=404, detail="Nenhum resultado para exportar.")

    output = io.StringIO()
    fields = ["nome", "caminho", "inativo", "riscos", "tamanho_mb", "last_scan"]
    writer = csv.DictWriter(output, fieldnames=fields, delimiter=";", extrasaction="ignore")
    writer.writeheader()
    writer.writerows(items)
    output.seek(0)

    filename = f"sentinel360_relatorio_{int(time.time())}.csv"
    return StreamingResponse(
        iter([output.getvalue().encode("utf-8-sig")]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Integrações — Microsoft 365 ───────────────────────────────────────────────

@app.post("/integrations/office365/configure")
async def configure_ms365(body: IntegrationConfigBody, username: str = Depends(get_current_user)):
    result = ms_graph.test_credentials(body.tenant_id, body.client_id, body.client_secret)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=f"Credenciais inválidas: {result['error']}")

    database.save_integration_config(username, "ms365", {
        "tenant_id":     body.tenant_id,
        "client_id":     body.client_id,
        "client_secret": body.client_secret,
        "org_name":      result.get("org_name", ""),
    })
    database.log_action("CONFIG_MS365", f"Org: {result.get('org_name', '')}", owner=username)
    return {"message": "Credenciais M365 salvas.", "org_name": result.get("org_name")}


@app.get("/integrations/office365/audit")
async def audit_ms365(inactive_days: int = 90, username: str = Depends(get_current_user)):
    config = database.get_integration_config(username, "ms365")
    if not config:
        raise HTTPException(status_code=404, detail="Credenciais M365 não configuradas.")

    try:
        users = ms_graph.audit_inactive_users_ms365(
            config["tenant_id"], config["client_id"], config["client_secret"],
            inactive_days=inactive_days,
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao consultar Microsoft Graph: {e}")

    database.log_action("AUDIT_MS365", f"Encontrados: {len(users)} inativos ({inactive_days}d)", owner=username)
    return {"inactive_users": users, "total": len(users)}


@app.post("/integrations/office365/scan-files")
async def scan_ms365_files(days: int = 180, username: str = Depends(get_current_user)):
    state = _get_scan_state(username)
    if state.is_scanning:
        raise HTTPException(status_code=409, detail="Varredura já em curso.")

    config = database.get_integration_config(username, "ms365")
    if not config:
        raise HTTPException(status_code=404, detail="Credenciais M365 não configuradas.")

    state.start("ms365")

    def _run():
        try:
            results = ms_graph.scan_sharepoint_files(
                config["tenant_id"], config["client_id"], config["client_secret"],
                days_threshold=days, progress_cb=state.on_file,
            )
            results += ms_graph.scan_onedrive_files(
                config["tenant_id"], config["client_id"], config["client_secret"],
                days_threshold=days, progress_cb=state.on_file,
            )
            database.save_cloud_results(username, "ms365", results)
            database.log_action("SCAN_MS365", f"Encontrados: {len(results)} | Dias: {days}", owner=username)
        except Exception as e:
            state.error = str(e)
            database.log_action("SCAN_MS365_ERRO", str(e), status="ERRO", owner=username)
        finally:
            state.finish()

    threading.Thread(target=_run, daemon=True).start()
    return {"message": f"Varredura MS365 iniciada (limiar: {days} dias)."}


@app.get("/integrations/office365/scan-status")
def cloud_scan_status(username: str = Depends(get_current_user)):
    state = _get_scan_state(username)
    return {
        "is_scanning":     state.is_scanning,
        "progress":        round(state.progress, 1),
        "provider":        state.provider,
        "error":           state.error,
        "processed_files": state.processed_files,
        "eta_seconds":     state.eta_seconds,
    }


@app.get("/integrations/office365/file-results")
def ms365_file_results(username: str = Depends(get_current_user)):
    return {"items": database.get_cloud_results(username, "ms365")}


# ── Integrações — Azure Active Directory ─────────────────────────────────────

@app.post("/integrations/azure/configure")
async def configure_azure(body: IntegrationConfigBody, username: str = Depends(get_current_user)):
    result = ms_graph.test_credentials(body.tenant_id, body.client_id, body.client_secret)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=f"Credenciais inválidas: {result['error']}")

    database.save_integration_config(username, "azure", {
        "tenant_id":     body.tenant_id,
        "client_id":     body.client_id,
        "client_secret": body.client_secret,
        "org_name":      result.get("org_name", ""),
    })
    database.log_action("CONFIG_AZURE", f"Org: {result.get('org_name', '')}", owner=username)
    return {"message": "Credenciais Azure AD salvas.", "org_name": result.get("org_name")}


@app.get("/integrations/azure/audit")
async def audit_azure(inactive_days: int = 90, username: str = Depends(get_current_user)):
    config = database.get_integration_config(username, "azure")
    if not config:
        raise HTTPException(status_code=404, detail="Credenciais Azure AD não configuradas.")

    try:
        users = ms_graph.audit_inactive_users_azure(
            config["tenant_id"], config["client_id"], config["client_secret"],
            inactive_days=inactive_days,
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao consultar Microsoft Graph: {e}")

    database.log_action("AUDIT_AZURE", f"Encontrados: {len(users)} inativos ({inactive_days}d)", owner=username)
    return {"inactive_users": users, "total": len(users)}


@app.post("/integrations/azure/scan-files")
async def scan_azure_files(days: int = 180, username: str = Depends(get_current_user)):
    state = _get_scan_state(username)
    if state.is_scanning:
        raise HTTPException(status_code=409, detail="Varredura já em curso.")

    config = database.get_integration_config(username, "azure")
    if not config:
        raise HTTPException(status_code=404, detail="Credenciais Azure AD não configuradas.")

    state.start("azure")

    def _run():
        try:
            results = ms_graph.scan_onedrive_files(
                config["tenant_id"], config["client_id"], config["client_secret"],
                days_threshold=days, progress_cb=state.on_file,
            )
            database.save_cloud_results(username, "azure", results)
            database.log_action("SCAN_AZURE", f"Encontrados: {len(results)} | Dias: {days}", owner=username)
        except Exception as e:
            state.error = str(e)
            database.log_action("SCAN_AZURE_ERRO", str(e), status="ERRO", owner=username)
        finally:
            state.finish()

    threading.Thread(target=_run, daemon=True).start()
    return {"message": f"Varredura Azure AD/OneDrive iniciada (limiar: {days} dias)."}


@app.get("/integrations/azure/file-results")
def azure_file_results(username: str = Depends(get_current_user)):
    return {"items": database.get_cloud_results(username, "azure")}


# ── Integrações — OneDrive pessoal (OAuth delegado) ──────────────────────────

@app.get("/auth/microsoft/login")
async def microsoft_login(username: str = Depends(get_current_user)):
    params = urllib.parse.urlencode({
        "client_id":     MS_CLIENT_ID,
        "response_type": "code",
        "redirect_uri":  MS_REDIRECT_URI,
        "scope":         MS_SCOPES,
        "response_mode": "query",
        "state":         username,
        "prompt":        "select_account",
    })
    url = f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?{params}"
    return {"auth_url": url}


@app.post("/auth/microsoft/exchange")
async def microsoft_exchange(body: MsExchangeBody):
    resp = req.post(
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        data={
            "client_id":     MS_CLIENT_ID,
            "client_secret": MS_CLIENT_SECRET,
            "code":          body.code,
            "redirect_uri":  MS_REDIRECT_URI,
            "grant_type":    "authorization_code",
        },
        timeout=15,
    )
    if resp.status_code != 200:
        raise HTTPException(status_code=400, detail="Falha ao trocar code por token.")

    tokens = resp.json()
    access_token  = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")

    me = req.get(
        "https://graph.microsoft.com/v1.0/me",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    ).json()
    ms_email = me.get("mail") or me.get("userPrincipalName", "")
    ms_name  = me.get("displayName", "")

    owner = body.state or "unknown"
    database.save_integration_config(owner, "ms_personal", {
        "type":          "delegated",
        "access_token":  access_token,
        "refresh_token": refresh_token,
        "ms_email":      ms_email,
        "ms_name":       ms_name,
    })
    database.log_action("OAUTH_MS", f"Conta pessoal conectada: {ms_email}", owner=owner)
    return {"connected": True, "ms_email": ms_email, "ms_name": ms_name}


@app.get("/auth/microsoft/callback")
async def microsoft_callback(request: Request):
    code  = request.query_params.get("code")
    state = request.query_params.get("state", "")
    error = request.query_params.get("error")

    if error:
        return RedirectResponse(f"{FRONTEND_URL}/integrations?ms_error={error}")
    if not code:
        return RedirectResponse(f"{FRONTEND_URL}/integrations?ms_error=no_code")

    resp = req.post(
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        data={
            "client_id":     MS_CLIENT_ID,
            "client_secret": MS_CLIENT_SECRET,
            "code":          code,
            "redirect_uri":  MS_REDIRECT_URI,
            "grant_type":    "authorization_code",
        },
        timeout=15,
    )
    if resp.status_code != 200:
        return RedirectResponse(f"{FRONTEND_URL}/integrations?ms_error=token_exchange_failed")

    tokens = resp.json()
    access_token  = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")

    me = req.get(
        "https://graph.microsoft.com/v1.0/me",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    ).json()
    ms_email = me.get("mail") or me.get("userPrincipalName", "")
    ms_name  = me.get("displayName", "")

    owner = state or "unknown"
    database.save_integration_config(owner, "ms_personal", {
        "type":          "delegated",
        "access_token":  access_token,
        "refresh_token": refresh_token,
        "ms_email":      ms_email,
        "ms_name":       ms_name,
    })
    database.log_action("OAUTH_MS", f"Conta pessoal conectada: {ms_email}", owner=owner)
    return RedirectResponse(f"{FRONTEND_URL}/integrations?ms_connected=1&ms_email={ms_email}")


@app.get("/auth/microsoft/status")
async def microsoft_status(username: str = Depends(get_current_user)):
    config = database.get_integration_config(username, "ms_personal")
    if config and config.get("access_token"):
        return {"connected": True, "ms_email": config.get("ms_email", ""), "ms_name": config.get("ms_name", "")}
    return {"connected": False}


@app.post("/integrations/personal/scan-files")
async def scan_personal_files(days: int = 180, username: str = Depends(get_current_user)):
    state = _get_scan_state(username)
    if state.is_scanning:
        raise HTTPException(status_code=409, detail="Varredura já em curso.")

    config = database.get_integration_config(username, "ms_personal")
    if not config or not config.get("access_token"):
        raise HTTPException(status_code=404, detail="Conta Microsoft não conectada.")

    state.start("personal")
    token = config["access_token"]

    def _run():
        try:
            results = ms_graph.scan_onedrive_personal(token, days_threshold=days, progress_cb=state.on_file)
            database.save_cloud_results(username, "personal", results)
            database.log_action("SCAN_PERSONAL", f"OneDrive pessoal: {len(results)} itens", owner=username)
        except Exception as e:
            state.error = str(e)
        finally:
            state.finish()

    threading.Thread(target=_run, daemon=True).start()
    return {"message": "Varredura do OneDrive pessoal iniciada."}


@app.get("/integrations/personal/file-results")
async def personal_file_results(username: str = Depends(get_current_user)):
    return {"items": database.get_cloud_results(username, "personal")}


# ── Relatório BI — Excel editável (abre no Power BI Desktop via "Obter Dados") ─

@app.get("/report/bi")
async def get_bi_report(username: str = Depends(get_current_user)):
    cloud_items  = database.get_cloud_results(owner=username)
    scan_history = database.get_scan_history(owner=username)
    xlsx_bytes = bi_excel.generate(cloud_items, scan_history)

    from datetime import date
    filename = f"sentinel360_bi_{date.today().isoformat()}.xlsx"
    return StreamingResponse(
        iter([xlsx_bytes]),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/ping")
async def ping():
    return {"status": "alive", "version": "2.1.0", "timestamp": time.time()}


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
