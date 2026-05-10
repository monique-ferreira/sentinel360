"""
Sentinel360 – API Principal (v2)
Multi-tenant | IA | Office 365 | Alertas
"""
import os
import time
import secrets
from contextlib import asynccontextmanager
from typing import Optional, List
from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException, Header, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

from core.database import (
    connect_db, disconnect_db,
    create_org, get_org, get_org_by_slug, update_org,
    create_user, get_user_by_username, get_user_by_email, get_users_by_org, update_user_last_login,
    create_agent, get_agents_by_org, get_agent_by_api_key, update_agent_status,
    create_scan, update_scan, get_scan, get_scans_by_org,
    bulk_insert_results, get_results, get_dashboard_stats,
    create_alert, get_alerts, acknowledge_alert,
)
from core.auth import (
    hash_password, verify_password,
    create_access_token, get_current_user, require_admin, require_analyst,
    generate_agent_key, CurrentUser,
)
from services.notifier import dispatch_alerts
from services.office365 import GraphClient


@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    yield
    await disconnect_db()

app = FastAPI(title="Sentinel360 API", version="2.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=os.getenv("ALBLOWED_ORIGINS", "http://localhost:5173").split(","), allow_methods=["*"], allow_headers=["*"])

class RegisterOrgRequest(BaseModel):
    org_name: str; org_slug: str; full_name: str; email: EmailStr; password: str
class LoginRequest(BaseModel):
    username: str; password: str
class CreateAgentRequest(BaseModel):
    name: str; hostname: str; platform: str
class ScanResultItem(BaseModel):
    name: str; path: str; extension: str; size_mb: float; last_accessed: str; last_modified: str; is_inactive: bool; risk_level: str; risks: list
class AgentScanPayload(BaseModel):
    scan_id: str; results: List[ScanResultItem]; total_files: int; processed_files: int; is_complete: bool = False
class Office365Config(BaseModel):
    tenant_id: str; client_id: str; client_secret: str
class AcknowledgeRequest(BaseModel):
    alert_id: str
class InviteUserRequest(BaseModel):
    email: EmailStr; username: str; password: str; role: str = "analyst"

@app.post("/auth/register")
async def register(body: RegisterOrgRequest):
    if await get_org_by_slug(body.org_slug): raise HTTPException(400, "Slug já em uso")
    org = await create_org({"name": body.org_name, "slug": body.org_slug, "plan": "free", "max_agents": 5, "max_users": 10, "created_at": datetime.utcnow(), "is_active": True})
    user = await create_user({"org_id": org["_id"], "email": body.email, "username": body.email.split("@")[0], "hashed_password": hash_password(body.password), "full_name": body.full_name, "role": "owner", "is_active": True, "created_at": datetime.utcnow()})
    token = create_access_token(user["_id"], org["_id"], "owner")
    return {"access_token": token, "token_type": "bearer", "org_id": org["_id"]}

@app.post("/auth/login")
async def login(body: LoginRequest):
    user = await get_user_by_username(body.username)
    if not user or not verify_password(body.password, user["hashed_password"]): raise HTTPException(401, "Credenciais inválidas")
    if not user.get("is_active"): raise HTTPException(403, "Conta desativada")
    await update_user_last_login(user["_id"])
    token = create_access_token(user["_id"], user["org_id"], user["role"])
    return {"access_token": token, "token_type": "bearer", "user": {"id": user["_id"], "email": user["email"], "role": user["role"], "full_name": user.get("full_name")}}

@app.get("/org")
async def get_organization(user=Depends(get_current_user)):
    org = await get_org(user.org_id)
    if not org: raise HTTPException(404)
    org.pop("office365_client_secret", None)
    return org

@app.post("/org/invite")
async def invite_user(body: InviteUserRequest, user=Depends(require_admin)):
    if await get_user_by_username(body.username): raise HTTPException(400, "Username já em uso")
    new_user = await create_user({"org_id": user.org_id, "email": body.email, "username": body.username, "hashed_password": hash_password(body.password), "role": body.role, "is_active": True, "created_at": datetime.utcnow()})
    new_user.pop("hashed_password", None)
    return new_user

@app.get("/org/users")
async def list_users(user=Depends(get_current_user)):
    users = await get_users_by_org(user.org_id)
    for u in users: u.pop("hashed_password", None)
    return users

@app.post("/agents")
async def register_agent(body: CreateAgentRequest, user=Depends(require_admin)):
    api_key = generate_agent_key()
    agent = await create_agent({"org_id": user.org_id, "name": body.name, "hostname": body.hostname, "platform": body.platform, "agent_version": "2.0.0", "api_key": api_key, "status": "offline", "tags": [], "created_at": datetime.utcnow()})
    return {"agent": agent, "api_key": api_key}

@app.get("/agents")
async def list_agents(user=Depends(get_current_user)):
    agents = await get_agents_by_org(user.org_id)
    for a in agents: a.pop("api_key", None)
    return agents

@app.post("/scans")
async def start_scan(days: int = Query(180, ge=1), user=Depends(require_analyst), x_agent_key: str = Header(...)):
    agent = await get_agent_by_api_key(x_agent_key)
    if not agent or agent["org_id"] != user.org_id: raise HTTPException(403)
    scan = await create_scan({"org_id": user.org_id, "agent_id": agent["_id"], "triggered_by": user.user_id, "status": "running", "days_threshold": days, "progress": 0.0, "started_at": datetime.utcnow(), "created_at": datetime.utcnow()})
    await update_agent_status(agent["_id"], "scanning")
    return {"scan_id": scan["_id"]}

@app.get("/scans")
async def list_scans(user=Depends(get_current_user)):
    return await get_scans_by_org(user.org_id)

@app.post("/ingest")
async def ingest_results(body: AgentScanPayload, background_tasks: BackgroundTasks, x_agent_key: str = Header(...)):
    agent = await get_agent_by_api_key(x_agent_key)
    if not agent: raise HTTPException(401)
    scan = await get_scan(body.scan_id)
    if not scan or scan["agent_id"] != agent["_id"]: raise HTTPException(403)
    docs = [{**r.dict(), "org_id": agent["org_id"], "scan_id": body.scan_id, "agent_id": agent["_id"], "detected_at": datetime.utcnow()} for r in body.results]
    count = await bulk_insert_results(docs)
    progress = (body.processed_files / body.total_files * 100) if body.total_files > 0 else 0
    update_data = {"processed_files": body.processed_files, "total_files": body.total_files, "progress": round(progress, 1), "results_count": scan.get("results_count", 0) + count}
    if body.is_complete:
        update_data.update({"status": "completed", "progress": 100.0, "finished_at": datetime.utcnow()})
        await update_agent_status(agent["_id"], "online")
        risky = [r for r in body.results if r.risk_level in ("critical", "high")]
        if risky:
            org = await get_org(agent["org_id"])
            background_tasks.add_task(dispatch_alerts, org, [r.dict() for r in risky])
    await update_scan(body.scan_id, update_data)
    return {"inserted": count, "progress": progress}

@app.get("/dashboard")
async def dashboard(user=Depends(get_current_user)):
    stats = await get_dashboard_stats(user.org_id)
    scans = await get_scans_by_org(user.org_id, limit=5)
    agents = await get_agents_by_org(user.org_id)
    for a in agents: a.pop("api_key", None)
    return {"stats": stats, "recent_scans": scans, "agents": agents}

@app.get("/results")
async def list_results(scan_id=None, risk_level=None, only_inactive: bool=False, skip: int=0, limit: int=100, user=Depends(get_current_user)):
    return await get_results(org_id=user.org_id, scan_id=scan_id, risk_level=risk_level, only_inactive=only_inactive, skip=skip, limit=limit)

@app.get("/alerts")
async def list_alerts(only_open: bool=True, user=Depends(get_current_user)):
    return await get_alerts(user.org_id, only_open=only_open)

@app.post("/alerts/acknowledge")
async def ack_alert(body: AcknowledgeRequest, user=Depends(require_analyst)):
    ok = await acknowledge_alert(body.alert_id, user.user_id)
    if not ok: raise HTTPException(404)
    return {"message": "Alerta reconhecido"}

@app.post("/integrations/office365/configure")
async def configure_office365(body: Office365Config, user=Depends(require_admin)):
    await update_org(user.org_id, {"office365_tenant_id": body.tenant_id, "office365_client_id": body.client_id, "office365_client_secret": body.client_secret})
    return {"message": "Oce 365 configurado"}

@app.get("/integrations/office365/audit")
async def office365_audit(inactive_days: int = 90, user=Depends(require_analyst)):
    org = await get_org(user.org_id)
    if not org.get("office365_tenant_id"): raise HTTPException(400, "Office 365 não configurado")
    graph = GraphClient(org["office365_tenant_id"], org["office365_client_id"], org.get("office365_client_secret", ""))
    return await graph.full_audit(inactive_days=inactive_days)

@app.get("/integrations/office365/users")
async def office365_users(user=Depends(require_analyst)):
    org = await get_org(user.org_id)
    graph = GraphClient(org["office365_tenant_id"], org["office365_client_id"], org.get("office365_client_secret", ""))
    return await graph.get_all_users()

@app.get("/ping")
async def ping():
    return {"status": "alive", "version": "2.0.0", "timestamp": time.time()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=True)
