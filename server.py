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

import asyncio
import csv
import hashlib
import hmac
import io
import os
import secrets
import threading
import time
import urllib.parse
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

import requests as req
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from pydantic import BaseModel

import auth_manager
import database
import ms_graph
import google_drive
import bi_report
import bi_excel

# ── OAuth Microsoft (delegated) ───────────────────────────────────────────────

MS_CLIENT_ID     = os.environ.get("MS_CLIENT_ID", "")
MS_CLIENT_SECRET = os.environ.get("MS_CLIENT_SECRET", "")
MS_REDIRECT_URI  = os.environ.get("MS_REDIRECT_URI", "https://sentinel360-cyber.vercel.app/integrations")
MS_SCOPES        = "Files.ReadWrite Sites.ReadWrite.All User.Read offline_access"
FRONTEND_URL     = os.environ.get("FRONTEND_URL", "https://sentinel360-cyber.vercel.app")
VT_API_KEY       = os.environ.get("VT_API_KEY", "")

# ── OAuth Google ──────────────────────────────────────────────────────────────

GCP_CLIENT_ID       = os.environ.get("GCP_CLIENT_ID", "")
GCP_CLIENT_SECRET   = os.environ.get("GCP_CLIENT_SECRET", "")
GCP_REDIRECT_URI    = os.environ.get("GCP_REDIRECT_URI", "https://sentinel360-cyber.vercel.app/integrations")

# ── Scheduled scan ────────────────────────────────────────────────────────────

_scheduler = AsyncIOScheduler()


async def _run_auto_scan(username: str):
    """Fires a background scan for the user using whatever integration is connected."""
    state = _get_scan_state(username)
    if state.is_scanning:
        return  # already running, skip this tick

    settings  = database.get_user_settings(username)
    days      = settings.get("inactivity_days", 180)

    async def _do():
        # Try MS365 first, then Azure, then personal
        cfg365 = database.get_integration_config(username, "ms365")
        cfgAzure = database.get_integration_config(username, "ms_azure")
        cfgPersonal = database.get_integration_config(username, "ms_personal")

        state.start("auto")
        try:
            results = []
            if cfg365 and cfg365.get("client_secret"):
                token = ms_graph._get_token(cfg365["tenant_id"], cfg365["client_id"], cfg365["client_secret"])
                results += ms_graph.scan_sharepoint_files(token, days_threshold=days, progress_cb=state.on_file)
                results += ms_graph.scan_onedrive_files(token, days_threshold=days, progress_cb=state.on_file)
            if cfgAzure and cfgAzure.get("client_secret"):
                token = ms_graph._get_token(cfgAzure["tenant_id"], cfgAzure["client_id"], cfgAzure["client_secret"])
                results += ms_graph.scan_onedrive_files(token, days_threshold=days, progress_cb=state.on_file)
            if cfgPersonal and cfgPersonal.get("access_token"):
                results += ms_graph.scan_onedrive_personal(cfgPersonal["access_token"], days_threshold=days, progress_cb=state.on_file)

            if results:
                database.save_cloud_results(username, "auto", results)
                database.log_action("AUTO_SCAN", f"{len(results)} arquivos analisados", owner=username)
        except Exception as e:
            state.error = str(e)
            print(f"[AUTO_SCAN] Erro para {username}: {e}")
        finally:
            state.finish()
            database.set_last_auto_scan(username, datetime.utcnow().isoformat())

    asyncio.create_task(_do())


def _schedule_user(username: str, interval: str, hour: int = 6, minute: int = 0, day: int = 1):
    """
    interval: daily | weekly | monthly
    hour:     0-23 (local server time, UTC on Render)
    day:      0-6 for weekly (0=Monday), 1-31 for monthly
    """
    job_id = f"scan_{username}"
    if _scheduler.get_job(job_id):
        _scheduler.remove_job(job_id)

    if interval == "daily":
        trigger = CronTrigger(hour=hour, minute=minute)
    elif interval == "weekly":
        trigger = CronTrigger(day_of_week=day, hour=hour, minute=minute)
    elif interval == "monthly":
        trigger = CronTrigger(day=day, hour=hour, minute=minute)
    else:
        return

    _scheduler.add_job(
        _run_auto_scan,
        trigger=trigger,
        id=job_id,
        args=[username],
        replace_existing=True,
        misfire_grace_time=3600,
    )
    print(f"[SCHEDULER] Agendado scan {interval} d={day} {hour:02d}:{minute:02d} para {username}")


def _unschedule_user(username: str):
    job_id = f"scan_{username}"
    if _scheduler.get_job(job_id):
        _scheduler.remove_job(job_id)


@asynccontextmanager
async def lifespan(app):
    _scheduler.start()
    # Load existing scheduled users from DB
    for user in database.get_users_with_auto_scan():
        _schedule_user(
            user["username"],
            user["auto_scan_interval"],
            hour=user.get("auto_scan_hour", 6),
            minute=user.get("auto_scan_minute", 0),
            day=user.get("auto_scan_day", 1),
        )
    yield
    _scheduler.shutdown(wait=False)

# ── App & CORS ────────────────────────────────────────────────────────────────

app = FastAPI(title="Sentinel360 API", version="2.1.0", lifespan=lifespan)

_DEBUG = os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")
_ALLOWED_ORIGINS = ["https://sentinel360-cyber.vercel.app"]
if _DEBUG:
    _ALLOWED_ORIGINS += ["http://localhost:5173", "http://localhost:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
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
    auto_scan_interval: Optional[str] = None  # "never" | "daily" | "weekly" | "monthly"
    auto_scan_hour:   Optional[int] = None  # 0-23
    auto_scan_minute: Optional[int] = None  # 0-59
    auto_scan_day:    Optional[int] = None  # 0-6 (weekly) or 1-31 (monthly)


class UserSettingsBody(BaseModel):
    inactivity_days: Optional[int] = None


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
            progress_frac = 1 - 1 / (1 + count / 50)
            if progress_frac > 0:
                estimated_total = elapsed / progress_frac
                self.eta_seconds = max(0, int(estimated_total - elapsed))
            else:
                self.eta_seconds = -1

    def finish(self):
        self.is_scanning = False
        self.progress    = 100.0
        self.eta_seconds = 0


_scan_states: dict[str, CloudScanState] = {}

# ── Simple rate limiter for login ─────────────────────────────────────────────
# Tracks failed attempts per key (username or IP); locks out after MAX_ATTEMPTS
_login_attempts: dict[str, list[float]] = {}
_LOGIN_WINDOW   = 300   # 5 minutes
_MAX_ATTEMPTS   = 10


def _check_login_rate(key: str):
    now = time.time()
    attempts = [t for t in _login_attempts.get(key, []) if now - t < _LOGIN_WINDOW]
    if len(attempts) >= _MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Muitas tentativas de login. Aguarde 5 minutos.")
    attempts.append(now)
    _login_attempts[key] = attempts


def _clear_login_rate(key: str):
    _login_attempts.pop(key, None)

# OAuth state nonces: {nonce: (username, expires_at)}
_oauth_states: dict[str, tuple[str, float]] = {}
_OAUTH_STATE_TTL = 600  # 10 minutes


def _create_oauth_state(username: str) -> str:
    nonce = secrets.token_urlsafe(32)
    _oauth_states[nonce] = (username, time.time() + _OAUTH_STATE_TTL)
    # Prune expired entries
    expired = [k for k, (_, exp) in _oauth_states.items() if time.time() > exp]
    for k in expired:
        _oauth_states.pop(k, None)
    return nonce


def _consume_oauth_state(nonce: str) -> str | None:
    """Returns the username bound to this nonce, or None if invalid/expired."""
    entry = _oauth_states.pop(nonce, None)
    if not entry:
        return None
    username, expires_at = entry
    if time.time() > expires_at:
        return None
    return username


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
        "inactivity_days":    settings.get("inactivity_days", 180),
        "auto_scan_interval": settings.get("auto_scan_interval", "never"),
        "auto_scan_hour":     settings.get("auto_scan_hour", 6),
        "auto_scan_minute":   settings.get("auto_scan_minute", 0),
        "auto_scan_day":      settings.get("auto_scan_day", 1),
        "last_auto_scan":     settings.get("last_auto_scan"),
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
    # Sync scheduler if auto_scan_interval changed
    if "auto_scan_interval" in updates or "auto_scan_hour" in updates or "auto_scan_day" in updates:
        fresh = database.get_user_settings(username)
        interval = fresh.get("auto_scan_interval", "never")
        if interval and interval != "never":
            _schedule_user(
                username, interval,
                hour=int(fresh.get("auto_scan_hour", 6)),
                minute=int(fresh.get("auto_scan_minute", 0)),
                day=int(fresh.get("auto_scan_day", 1)),
            )
        else:
            _unschedule_user(username)
    return {"message": "Perfil atualizado."}


@app.get("/user/settings")
async def get_user_settings_ep(username: str = Depends(get_current_user)):
    s = database.get_user_settings(username)
    return {
        "inactivity_days": s.get("inactivity_days", 180),
        "vt_configured": bool(VT_API_KEY),
    }


@app.put("/user/settings")
async def put_user_settings(body: UserSettingsBody, username: str = Depends(get_current_user)):
    updates: dict = {}
    if body.inactivity_days is not None:
        updates["inactivity_days"] = body.inactivity_days
    if updates:
        database.update_user_settings(username, updates)
    return {"message": "Configurações salvas.", **updates}


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
async def login(body: LoginBody, request: Request):
    ip = request.client.host if request.client else "unknown"
    _check_login_rate(f"ip:{ip}")
    _check_login_rate(f"user:{body.username}")

    user = database.find_user(body.username)
    if not user or not auth_manager.verify_password(body.password, user["password"]):
        raise HTTPException(status_code=401, detail="Usuário ou senha incorretos.")

    _clear_login_rate(f"ip:{ip}")
    _clear_login_rate(f"user:{body.username}")
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


_MIME_MAP = {
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
    ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
    ".svg": "image/svg+xml", ".pdf": "application/pdf",
}

@app.get("/file-preview")
async def file_preview(path: str, target_username: str = "", username: str = Depends(get_current_user)):
    """Retorna o conteúdo de um arquivo (texto, imagem ou PDF) para visualização."""
    owner = username
    if target_username and target_username != username:
        # Admin visualizando arquivo de membro — verificar permissão
        me = database.get_user_settings(username)
        if not me or me.get("org_role") != "admin":
            raise HTTPException(status_code=403, detail="Acesso negado.")
        owner = target_username
    all_items = database.get_cloud_results(owner=owner)
    item = next((i for i in all_items if (i.get("caminho") or i.get("Caminho") or i.get("path")) == path), None)
    if not item:
        raise HTTPException(status_code=404, detail="Item não encontrado nos resultados.")

    drive_id = item.get("graph_drive_id", "")
    item_id  = item.get("graph_item_id", "")
    if not drive_id or not item_id:
        raise HTTPException(status_code=422, detail="IDs do arquivo não disponíveis. Refaça o scan.")

    nome = item.get("nome") or item.get("Arquivo") or item.get("name", "")
    ext  = ("." + nome.rsplit(".", 1)[-1].lower()) if "." in nome else ""
    mime = _MIME_MAP.get(ext, "")
    is_binary = bool(mime)
    MAX_BYTES = 0 if is_binary else 50 * 1024  # 0 = sem limite para binários

    # ── Google Drive ──────────────────────────────────────────────────────────
    if drive_id == "gdrive":
        gdrive_cfg = database.get_integration_config(owner, "google_personal")
        if not gdrive_cfg or not gdrive_cfg.get("access_token"):
            raise HTTPException(status_code=400, detail="Conta Google não conectada.")
        access_token = gdrive_cfg["access_token"]
        # Refresh if needed
        if gdrive_cfg.get("refresh_token"):
            try:
                access_token = google_drive.refresh_access_token(
                    GCP_CLIENT_ID, GCP_CLIENT_SECRET, gdrive_cfg["refresh_token"]
                )
                gdrive_cfg["access_token"] = access_token
                database.save_integration_config(owner, "google_personal", gdrive_cfg)
            except Exception:
                pass
        try:
            import requests as _req
            resp = _req.get(
                f"https://www.googleapis.com/drive/v3/files/{item_id}?alt=media",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=20,
                stream=True,
            )
            resp.raise_for_status()
            raw = b""
            chunk_size = MAX_BYTES if MAX_BYTES else 65536
            for chunk in resp.iter_content(chunk_size=chunk_size):
                raw += chunk
                if MAX_BYTES and len(raw) >= MAX_BYTES:
                    break
            if MAX_BYTES:
                raw = raw[:MAX_BYTES]
        except Exception:
            raise HTTPException(status_code=502, detail="Não foi possível ler o arquivo. Tente novamente.")

    # ── Microsoft Graph ───────────────────────────────────────────────────────
    else:
        cfg = database.get_integration_config(username, "ms_personal")
        if cfg and cfg.get("access_token"):
            access_token = cfg["access_token"]
        else:
            cfg365 = database.get_integration_config(username, "ms365")
            if not cfg365:
                raise HTTPException(status_code=400, detail="Nenhuma conta Microsoft conectada.")
            access_token = ms_graph._get_token(
                cfg365["tenant_id"], cfg365["client_id"], cfg365["client_secret"]
            )
        try:
            import requests as _req
            resp = _req.get(
                f"https://graph.microsoft.com/v1.0/drives/{drive_id}/items/{item_id}/content",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=20,
                stream=True,
            )
            resp.raise_for_status()
            raw = b""
            chunk_size = MAX_BYTES if MAX_BYTES else 65536
            for chunk in resp.iter_content(chunk_size=chunk_size):
                raw += chunk
                if MAX_BYTES and len(raw) >= MAX_BYTES:
                    break
            if MAX_BYTES:
                raw = raw[:MAX_BYTES]
        except Exception:
            raise HTTPException(status_code=502, detail="Não foi possível ler o arquivo. Tente novamente.")

    if is_binary:
        import base64 as _b64
        return {
            "nome": nome,
            "type": "binary",
            "mime": mime,
            "data": _b64.b64encode(raw).decode(),
            "truncated": False,
        }

    return {
        "nome": nome,
        "type": "text",
        "content": raw.decode("utf-8", errors="ignore"),
        "truncated": len(raw) >= MAX_BYTES,
    }


@app.get("/virustotal/check")
async def virustotal_check(path: str, target_username: str = "", username: str = Depends(get_current_user)):
    """Verifica o hash SHA256 de um arquivo no VirusTotal."""
    owner = username
    if target_username and target_username != username:
        me = database.get_user_settings(username)
        if not me or me.get("org_role") != "admin":
            raise HTTPException(status_code=403, detail="Acesso negado.")
        owner = target_username

    if not VT_API_KEY:
        raise HTTPException(status_code=503, detail="VirusTotal não configurado no servidor.")

    # Buscar hash do item no banco
    all_items = database.get_cloud_results(owner=owner)
    item = next((i for i in all_items if (i.get("caminho") or i.get("Caminho") or i.get("path")) == path), None)
    if not item:
        raise HTTPException(status_code=404, detail="Item não encontrado nos resultados.")

    sha256 = item.get("sha256", "")
    if not sha256:
        raise HTTPException(status_code=422, detail="Hash SHA256 não disponível para este arquivo. Refaça o scan para calculá-lo.")

    # Verificar cache — se o hash já foi analisado, retornar direto
    cached = database.get_vt_cache(sha256)
    if cached:
        cached.pop("cached_at", None)
        return {**cached, "from_cache": True}

    import requests as _req
    try:
        resp = _req.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": VT_API_KEY},
            timeout=15,
        )
    except Exception:
        raise HTTPException(status_code=502, detail="Não foi possível contatar o VirusTotal. Tente novamente.")

    if resp.status_code == 404:
        result = {"status": "not_found", "sha256": sha256}
        database.set_vt_cache(sha256, result)
        return result
    if resp.status_code == 401:
        raise HTTPException(status_code=401, detail="Chave da API do VirusTotal inválida.")
    if resp.status_code == 429:
        raise HTTPException(status_code=429, detail="Limite de requisições do VirusTotal atingido. Aguarde 1 minuto.")
    if not resp.ok:
        raise HTTPException(status_code=502, detail=f"VirusTotal retornou {resp.status_code}.")

    data = resp.json().get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})
    engines = data.get("last_analysis_results", {})

    detections = [
        {"engine": name, "category": res.get("category"), "result": res.get("result")}
        for name, res in engines.items()
        if res.get("category") in ("malicious", "suspicious")
    ]

    result = {
        "status": "found",
        "sha256": sha256,
        "meaningful_name": data.get("meaningful_name", ""),
        "type_description": data.get("type_description", ""),
        "stats": stats,
        "detections": detections,
        "threat_names": data.get("threat_names", []) or list({d["result"] for d in detections if d["result"]}),
        "vt_link": f"https://www.virustotal.com/gui/file/{sha256}",
        "analysis_date": data.get("last_analysis_date"),
        "from_cache": False,
    }
    database.set_vt_cache(sha256, result)
    return result


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
    state_nonce = _create_oauth_state(username)
    params = urllib.parse.urlencode({
        "client_id":     MS_CLIENT_ID,
        "response_type": "code",
        "redirect_uri":  MS_REDIRECT_URI,
        "scope":         MS_SCOPES,
        "response_mode": "query",
        "state":         state_nonce,
        "prompt":        "select_account",
    })
    url = f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?{params}"
    return {"auth_url": url}


@app.post("/auth/microsoft/exchange")
async def microsoft_exchange(body: MsExchangeBody, username: str = Depends(get_current_user)):
    # Validate nonce — must match the authenticated user who initiated the flow
    nonce_owner = _consume_oauth_state(body.state)
    if not nonce_owner or nonce_owner != username:
        raise HTTPException(status_code=400, detail="Estado OAuth inválido ou expirado.")

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

    database.save_integration_config(username, "ms_personal", {
        "type":          "delegated",
        "access_token":  access_token,
        "refresh_token": refresh_token,
        "ms_email":      ms_email,
        "ms_name":       ms_name,
    })
    database.log_action("OAUTH_MS", f"Conta pessoal conectada: {ms_email}", owner=username)
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

    nonce_owner = _consume_oauth_state(state)
    if not nonce_owner:
        return RedirectResponse(f"{FRONTEND_URL}/integrations?ms_error=invalid_state")

    database.save_integration_config(nonce_owner, "ms_personal", {
        "type":          "delegated",
        "access_token":  access_token,
        "refresh_token": refresh_token,
        "ms_email":      ms_email,
        "ms_name":       ms_name,
    })
    database.log_action("OAUTH_MS", f"Conta pessoal conectada: {ms_email}", owner=nonce_owner)
    # Don't echo email in redirect URL — frontend fetches it via /auth/microsoft/status
    return RedirectResponse(f"{FRONTEND_URL}/integrations?ms_connected=1")


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


# ── Google Drive OAuth ────────────────────────────────────────────────────────

class GdriveConfigBody(BaseModel):
    service_account_json: dict  # JSON do service account para Workspace

@app.get("/auth/google/login")
async def google_login(username: str = Depends(get_current_user)):
    if not GCP_CLIENT_ID:
        raise HTTPException(status_code=503, detail="Google OAuth não configurado no servidor.")
    state_nonce = _create_oauth_state(username)
    url = google_drive.get_auth_url(GCP_CLIENT_ID, GCP_REDIRECT_URI, state=state_nonce)
    return {"auth_url": url}


@app.get("/auth/google/callback")
async def google_callback(request: Request):
    code  = request.query_params.get("code")
    state = request.query_params.get("state", "")
    error = request.query_params.get("error")

    if error:
        return RedirectResponse(f"{FRONTEND_URL}/integrations?gdrive_error={error}")
    if not code:
        return RedirectResponse(f"{FRONTEND_URL}/integrations?gdrive_error=no_code")

    nonce_owner = _consume_oauth_state(state)
    if not nonce_owner:
        return RedirectResponse(f"{FRONTEND_URL}/integrations?gdrive_error=invalid_state")

    try:
        tokens = google_drive.exchange_code(GCP_CLIENT_ID, GCP_CLIENT_SECRET, GCP_REDIRECT_URI, code)
    except Exception:
        return RedirectResponse(f"{FRONTEND_URL}/integrations?gdrive_error=token_exchange_failed")

    access_token  = tokens.get("access_token", "")
    refresh_token = tokens.get("refresh_token", "")

    try:
        info = google_drive.get_user_info(access_token)
        gdrive_email = info.get("email", "")
        gdrive_name  = info.get("name", "")
    except Exception:
        gdrive_email = ""
        gdrive_name  = ""

    database.save_integration_config(nonce_owner, "google_personal", {
        "type":          "delegated",
        "access_token":  access_token,
        "refresh_token": refresh_token,
        "gdrive_email":  gdrive_email,
        "gdrive_name":   gdrive_name,
    })
    database.log_action("OAUTH_GOOGLE", f"Google Drive pessoal conectado: {gdrive_email}", owner=nonce_owner)
    return RedirectResponse(f"{FRONTEND_URL}/integrations?gdrive_connected=1")


@app.get("/auth/google/status")
async def google_status(username: str = Depends(get_current_user)):
    config = database.get_integration_config(username, "google_personal")
    if config and config.get("access_token"):
        return {"connected": True, "gdrive_email": config.get("gdrive_email", ""), "gdrive_name": config.get("gdrive_name", "")}
    return {"connected": False}


@app.post("/integrations/google-workspace/configure")
async def configure_google_workspace(body: GdriveConfigBody, username: str = Depends(get_current_user)):
    me = database.get_user_settings(username)
    if me.get("account_type") != "corporate" or me.get("org_role") != "admin":
        raise HTTPException(status_code=403, detail="Apenas admins corporativos podem configurar o Workspace.")
    result = google_drive.test_service_account(body.service_account_json)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=f"Credenciais inválidas: {result['error']}")
    database.save_integration_config(username, "google_workspace", {
        "type":                 "service_account",
        "service_account_json": body.service_account_json,
    })
    return {"message": "Google Workspace configurado com sucesso."}


@app.get("/integrations/google-workspace/status")
async def google_workspace_status(username: str = Depends(get_current_user)):
    config = database.get_integration_config(username, "google_workspace")
    if config and config.get("service_account_json"):
        sa = config["service_account_json"]
        return {"connected": True, "client_email": sa.get("client_email", "")}
    return {"connected": False}


@app.post("/integrations/google/scan-files")
async def scan_google_files(
    provider: str = "personal",  # "personal" | "workspace"
    days: int = 180,
    username: str = Depends(get_current_user),
):
    state = _get_scan_state(username)
    if state.is_scanning:
        raise HTTPException(status_code=409, detail="Varredura já em curso.")

    if provider == "workspace":
        me = database.get_user_settings(username)
        if me.get("account_type") != "corporate" or me.get("org_role") != "admin":
            raise HTTPException(status_code=403, detail="Apenas admins corporativos.")
        cfg = database.get_integration_config(username, "google_workspace")
        if not cfg or not cfg.get("service_account_json"):
            raise HTTPException(status_code=400, detail="Google Workspace não configurado.")

        def _run_workspace():
            state.start("google_workspace")
            try:
                result = google_drive.test_service_account(cfg["service_account_json"])
                if not result["ok"]:
                    state.error = "Credenciais do service account inválidas."
                    return
                access_token = result["token"]
                results = google_drive.scan_drive_files(access_token, days_threshold=days, progress_cb=state.on_file, shared_drives=True)
                database.save_cloud_results(username, "google_workspace", results)
                database.log_action("SCAN_GOOGLE_WS", f"{len(results)} arquivos analisados", owner=username)
            except Exception as e:
                state.error = str(e)
            finally:
                state.finish()

        threading.Thread(target=_run_workspace, daemon=True).start()
        return {"status": "started"}

    # personal
    cfg = database.get_integration_config(username, "google_personal")
    if not cfg or not cfg.get("access_token"):
        raise HTTPException(status_code=400, detail="Google Drive pessoal não conectado.")

    def _run_personal():
        state.start("google_personal")
        try:
            access_token = cfg["access_token"]
            # Try to refresh if needed
            if cfg.get("refresh_token") and GCP_CLIENT_ID:
                try:
                    access_token = google_drive.refresh_access_token(GCP_CLIENT_ID, GCP_CLIENT_SECRET, cfg["refresh_token"])
                    database.save_integration_config(username, "google_personal", {**cfg, "access_token": access_token})
                except Exception:
                    pass  # use existing token
            results = google_drive.scan_drive_files(access_token, days_threshold=days, progress_cb=state.on_file, shared_drives=False)
            database.save_cloud_results(username, "google_personal", results)
            database.log_action("SCAN_GOOGLE", f"{len(results)} arquivos analisados", owner=username)
        except Exception as e:
            state.error = str(e)
        finally:
            state.finish()

    threading.Thread(target=_run_personal, daemon=True).start()
    return {"status": "started"}


@app.get("/integrations/google/scan-status")
async def google_scan_status(username: str = Depends(get_current_user)):
    state = _get_scan_state(username)
    return {
        "is_scanning":     state.is_scanning,
        "progress":        state.progress,
        "processed_files": state.processed_files,
        "eta_seconds":     state.eta_seconds,
        "error":           state.error,
        "provider":        state.provider,
    }


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/ping")
async def ping():
    return {"status": "alive", "version": "2.1.0", "timestamp": time.time()}


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
