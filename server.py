"""
server.py — API FastAPI do Sentinel360

Endpoints:
  Auth:        POST /register  POST /login  POST /forgot-password
  Scan:        POST /scan  GET /scan-status
  Results:     GET /results  DELETE /delete-item  GET /export/csv
  Integrations:
    POST /integrations/office365/configure   GET /integrations/office365/audit
    POST /integrations/office365/scan-files  GET /integrations/office365/file-results
    POST /integrations/azure/configure       GET /integrations/azure/audit
    POST /integrations/azure/scan-files      GET /integrations/azure/file-results
  Report:      GET /report/bi
  Health:      GET /ping
"""

import csv
import io
import json
import os
import threading
import time
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from pydantic import BaseModel, EmailStr

import auth_manager
import database
import ms_graph
import bi_report

# ── OAuth Microsoft (delegated) ───────────────────────────────────────────────

MS_CLIENT_ID     = os.environ.get("MS_CLIENT_ID", "")
MS_CLIENT_SECRET = os.environ.get("MS_CLIENT_SECRET", "")
MS_REDIRECT_URI  = os.environ.get("MS_REDIRECT_URI", "https://sentinel360.onrender.com/auth/microsoft/callback")
MS_SCOPES        = "Files.Read Sites.Read.All User.Read offline_access"
FRONTEND_URL     = os.environ.get("FRONTEND_URL", "https://sentinel360-cyber.vercel.app")

# ── App & CORS ────────────────────────────────────────────────────────────────

app = FastAPI(title="Sentinel360 API", version="2.0.0")

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
    org_name: Optional[str] = None
    org_slug: Optional[str] = None


class LoginBody(BaseModel):
    username: str
    password: str


class ForgotPasswordBody(BaseModel):
    email: str


class IntegrationConfigBody(BaseModel):
    tenant_id: str
    client_id: str
    client_secret: str


class CloudScanState:
    def __init__(self):
        self.is_scanning = False
        self.progress    = 0.0
        self.provider    = ""
        self.error       = ""


cloud_state = CloudScanState()

# ── Autenticação via JWT ──────────────────────────────────────────────────────

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


async def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    """Dependência: valida JWT e retorna username."""
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


# ── Endpoints de autenticação ─────────────────────────────────────────────────

@app.post("/register", status_code=201)
async def register(body: RegisterBody):
    if database.find_user(body.username):
        raise HTTPException(status_code=409, detail="Usuário já cadastrado.")
    if body.email and database.find_user_by_email(body.email):
        raise HTTPException(status_code=409, detail="Email já cadastrado.")

    database.create_user({
        "username":  body.username,
        "password":  auth_manager.get_password_hash(body.password),
        "email":     body.email,
        "full_name": body.full_name,
        "org_name":  body.org_name,
        "org_slug":  body.org_slug,
        "created_at": time.time(),
    })
    database.log_action("REGISTRO", f"Novo usuário: {body.username}")
    return {"message": "Conta criada com sucesso."}


@app.post("/login")
async def login(body: LoginBody):
    user = database.find_user(body.username)
    if not user or not auth_manager.verify_password(body.password, user["password"]):
        raise HTTPException(status_code=401, detail="Usuário ou senha incorretos.")

    token = auth_manager.create_access_token({"sub": body.username})
    database.log_action("LOGIN", f"Usuário autenticado: {body.username}")
    return {"access_token": token, "token_type": "bearer"}


@app.post("/forgot-password")
async def forgot_password(body: ForgotPasswordBody):
    """
    Registra a solicitação de recuperação de senha.
    Em produção: enviar email com link de redefinição.
    Retorna 200 sempre (não vaza se email existe).
    """
    user = database.find_user_by_email(body.email)
    if user:
        database.log_action("RECUPERAÇÃO_SENHA", f"Solicitação para: {body.email}")
        # TODO: integrar com serviço de email (SendGrid, SES, etc.)
    return {"message": "Se o email existir no sistema, você receberá instruções em breve."}


@app.get("/results")
def get_results(_: str = Depends(get_current_user)):
    return {"items": database.get_cloud_results()}


@app.get("/export/csv")
def export_csv(_: str = Depends(get_current_user)):
    items = database.get_cloud_results()
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
async def configure_ms365(
    body: IntegrationConfigBody,
    _: str = Depends(get_current_user),
):
    """
    Salva credenciais do Microsoft 365 e valida a conectividade.

    Permissões necessárias no App Registration:
      Mail.Read · Sites.Read.All · Files.Read.All · User.Read.All · AuditLog.Read.All
    """
    # Testa as credenciais antes de salvar
    result = ms_graph.test_credentials(body.tenant_id, body.client_id, body.client_secret)
    if not result["ok"]:
        raise HTTPException(
            status_code=400,
            detail=f"Credenciais inválidas ou sem permissão: {result['error']}",
        )

    database.save_integration_config("ms365", {
        "tenant_id": body.tenant_id,
        "client_id": body.client_id,
        "client_secret": body.client_secret,  # armazenado criptografado em produção
        "org_name": result.get("org_name", ""),
    })
    database.log_action("CONFIG_MS365", f"Org: {result.get('org_name', '')}")
    return {"message": "Credenciais M365 salvas.", "org_name": result.get("org_name")}


@app.get("/integrations/office365/audit")
async def audit_ms365(
    inactive_days: int = 90,
    _: str = Depends(get_current_user),
):
    """Lista usuários inativos do Microsoft 365."""
    config = database.get_integration_config("ms365")
    if not config:
        raise HTTPException(status_code=404, detail="Credenciais M365 não configuradas.")

    try:
        users = ms_graph.audit_inactive_users_ms365(
            config["tenant_id"],
            config["client_id"],
            config["client_secret"],
            inactive_days=inactive_days,
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao consultar Microsoft Graph: {e}")

    database.log_action("AUDIT_MS365", f"Encontrados: {len(users)} inativos ({inactive_days}d)")
    return {"inactive_users": users, "total": len(users)}


# ── Integrações — Azure Active Directory ─────────────────────────────────────

@app.post("/integrations/azure/configure")
async def configure_azure(
    body: IntegrationConfigBody,
    _: str = Depends(get_current_user),
):
    """
    Salva credenciais do Azure AD e valida a conectividade.

    Permissões necessárias no App Registration:
      User.Read.All · Directory.Read.All · AuditLog.Read.All
    Após adicionar: conceda admin consent para a organização.
    """
    result = ms_graph.test_credentials(body.tenant_id, body.client_id, body.client_secret)
    if not result["ok"]:
        raise HTTPException(
            status_code=400,
            detail=f"Credenciais inválidas ou sem permissão: {result['error']}",
        )

    database.save_integration_config("azure", {
        "tenant_id": body.tenant_id,
        "client_id": body.client_id,
        "client_secret": body.client_secret,
        "org_name": result.get("org_name", ""),
    })
    database.log_action("CONFIG_AZURE", f"Org: {result.get('org_name', '')}")
    return {"message": "Credenciais Azure AD salvas.", "org_name": result.get("org_name")}


@app.get("/integrations/azure/audit")
async def audit_azure(
    inactive_days: int = 90,
    _: str = Depends(get_current_user),
):
    """Lista usuários inativos do Azure Active Directory."""
    config = database.get_integration_config("azure")
    if not config:
        raise HTTPException(status_code=404, detail="Credenciais Azure AD não configuradas.")

    try:
        users = ms_graph.audit_inactive_users_azure(
            config["tenant_id"],
            config["client_id"],
            config["client_secret"],
            inactive_days=inactive_days,
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao consultar Microsoft Graph: {e}")

    database.log_action("AUDIT_AZURE", f"Encontrados: {len(users)} inativos ({inactive_days}d)")
    return {"inactive_users": users, "total": len(users)}


# ── Integrações — Varredura de arquivos cloud ─────────────────────────────────

@app.post("/integrations/office365/scan-files")
async def scan_ms365_files(
    days: int = 180,
    _: str = Depends(get_current_user),
):
    """
    Dispara varredura de arquivos SharePoint + OneDrive em background.
    Permissões: Sites.Read.All · Files.Read.All · User.Read.All
    """
    if cloud_state.is_scanning:
        raise HTTPException(status_code=409, detail="Varredura cloud já em curso.")
    config = database.get_integration_config("ms365")
    if not config:
        raise HTTPException(status_code=404, detail="Credenciais M365 não configuradas.")

    cloud_state.is_scanning = True
    cloud_state.progress    = 0.0
    cloud_state.provider    = "ms365"
    cloud_state.error       = ""

    def _run():
        try:
            class Ref:
                progress = 0.0
            ref = Ref()
            results = ms_graph.scan_sharepoint_files(
                config["tenant_id"], config["client_id"], config["client_secret"],
                days_threshold=days, state_ref=ref,
            )
            cloud_state.progress = 50.0
            results += ms_graph.scan_onedrive_files(
                config["tenant_id"], config["client_id"], config["client_secret"],
                days_threshold=days,
            )
            database.save_cloud_results("ms365", results)
            database.log_action("SCAN_MS365", f"Encontrados: {len(results)} | Dias: {days}")
        except Exception as e:
            cloud_state.error = str(e)
            database.log_action("SCAN_MS365_ERRO", str(e), status="ERRO")
        finally:
            cloud_state.is_scanning = False
            cloud_state.progress    = 100.0

    threading.Thread(target=_run, daemon=True).start()
    return {"message": f"Varredura MS365 iniciada (limiar: {days} dias)."}


@app.get("/integrations/office365/scan-status")
def cloud_scan_status(_: str = Depends(get_current_user)):
    return {
        "is_scanning": cloud_state.is_scanning,
        "progress":    round(cloud_state.progress, 1),
        "provider":    cloud_state.provider,
        "error":       cloud_state.error,
    }


@app.get("/integrations/office365/file-results")
def ms365_file_results(_: str = Depends(get_current_user)):
    """Retorna resultados da última varredura SharePoint/OneDrive."""
    return {"items": database.get_cloud_results("ms365")}


@app.post("/integrations/azure/scan-files")
async def scan_azure_files(
    days: int = 180,
    _: str = Depends(get_current_user),
):
    """
    Dispara varredura de arquivos OneDrive via credenciais Azure AD.
    Permissões: User.Read.All · Files.Read.All
    """
    if cloud_state.is_scanning:
        raise HTTPException(status_code=409, detail="Varredura cloud já em curso.")
    config = database.get_integration_config("azure")
    if not config:
        raise HTTPException(status_code=404, detail="Credenciais Azure AD não configuradas.")

    cloud_state.is_scanning = True
    cloud_state.progress    = 0.0
    cloud_state.provider    = "azure"
    cloud_state.error       = ""

    def _run():
        try:
            results = ms_graph.scan_onedrive_files(
                config["tenant_id"], config["client_id"], config["client_secret"],
                days_threshold=days,
            )
            database.save_cloud_results("azure", results)
            database.log_action("SCAN_AZURE", f"Encontrados: {len(results)} | Dias: {days}")
        except Exception as e:
            cloud_state.error = str(e)
            database.log_action("SCAN_AZURE_ERRO", str(e), status="ERRO")
        finally:
            cloud_state.is_scanning = False
            cloud_state.progress    = 100.0

    threading.Thread(target=_run, daemon=True).start()
    return {"message": f"Varredura Azure AD/OneDrive iniciada (limiar: {days} dias)."}


@app.get("/integrations/azure/file-results")
def azure_file_results(_: str = Depends(get_current_user)):
    return {"items": database.get_cloud_results("azure")}


# ── Relatório BI ──────────────────────────────────────────────────────────────

@app.get("/report/bi", response_class=HTMLResponse)
async def get_bi_report(_: str = Depends(get_current_user)):
    """Gera e retorna relatório BI HTML completo com Chart.js."""
    local_items   = database.get_all_results()
    cloud_items   = database.get_cloud_results()
    scan_history  = database.get_scan_history()
    html = bi_report.generate(local_items, cloud_items, scan_history)
    return HTMLResponse(content=html)


# ── OAuth Microsoft — fluxo delegado (sem admin consent) ─────────────────────

@app.get("/auth/microsoft/login")
async def microsoft_login(state: str = "", _: str = Depends(get_current_user)):
    """Retorna URL de autorização Microsoft. state deve conter o username do Sentinel."""
    import urllib.parse
    params = urllib.parse.urlencode({
        "client_id":     MS_CLIENT_ID,
        "response_type": "code",
        "redirect_uri":  MS_REDIRECT_URI,
        "scope":         MS_SCOPES,
        "response_mode": "query",
        "state":         state,
        "prompt":        "select_account",
    })
    url = f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?{params}"
    return {"auth_url": url}


@app.get("/auth/microsoft/callback")
async def microsoft_callback(request: Request):
    """Recebe o code do Microsoft, troca por token e redireciona para o frontend."""
    code  = request.query_params.get("code")
    state = request.query_params.get("state", "")
    error = request.query_params.get("error")

    if error:
        return RedirectResponse(f"{FRONTEND_URL}/integrations?ms_error={error}")

    if not code:
        return RedirectResponse(f"{FRONTEND_URL}/integrations?ms_error=no_code")

    # Troca o code por access_token + refresh_token
    import requests as req
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

    # Busca info do usuário Microsoft
    me = req.get(
        "https://graph.microsoft.com/v1.0/me",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    ).json()
    ms_email = me.get("mail") or me.get("userPrincipalName", "")
    ms_name  = me.get("displayName", "")

    # Salva token delegado no banco associado ao state (username Sentinel)
    database.save_integration_config(f"ms_personal_{state}" if state else "ms_personal", {
        "type":          "delegated",
        "access_token":  access_token,
        "refresh_token": refresh_token,
        "ms_email":      ms_email,
        "ms_name":       ms_name,
    })
    database.log_action("OAUTH_MS", f"Conta pessoal conectada: {ms_email}")

    return RedirectResponse(f"{FRONTEND_URL}/integrations?ms_connected=1&ms_email={ms_email}")


@app.get("/auth/microsoft/status")
async def microsoft_status(username: str = Depends(get_current_user)):
    """Retorna se o usuário tem conta Microsoft conectada."""
    config = database.get_integration_config(f"ms_personal_{username}")
    if config and config.get("access_token"):
        return {"connected": True, "ms_email": config.get("ms_email", ""), "ms_name": config.get("ms_name", "")}
    return {"connected": False}


@app.post("/integrations/personal/scan-files")
async def scan_personal_files(days: int = 180, username: str = Depends(get_current_user)):
    """Varre OneDrive pessoal usando token delegado do usuário."""
    config = database.get_integration_config(f"ms_personal_{username}")
    if not config or not config.get("access_token"):
        raise HTTPException(status_code=404, detail="Conta Microsoft não conectada.")

    if cloud_state.is_scanning:
        raise HTTPException(status_code=409, detail="Varredura já em curso.")

    cloud_state.is_scanning = True
    cloud_state.progress    = 0.0
    cloud_state.provider    = "personal"
    cloud_state.error       = ""

    token = config["access_token"]

    def _run():
        try:
            results = ms_graph.scan_onedrive_personal(token, days_threshold=days)
            database.save_cloud_results(f"personal_{username}", results)
            database.log_action("SCAN_PERSONAL", f"OneDrive pessoal: {len(results)} itens")
        except Exception as e:
            cloud_state.error = str(e)
        finally:
            cloud_state.is_scanning = False
            cloud_state.progress    = 100.0

    threading.Thread(target=_run, daemon=True).start()
    return {"message": "Varredura do OneDrive pessoal iniciada."}


@app.get("/integrations/personal/file-results")
async def personal_file_results(username: str = Depends(get_current_user)):
    return {"items": database.get_cloud_results(f"personal_{username}")}


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/ping")
async def ping():
    return {"status": "alive", "version": "2.0.0", "timestamp": time.time()}


# ── Entry point ───────────────────────────────────────────────────────────────


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
