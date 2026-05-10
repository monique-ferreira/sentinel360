"""
Sentinel360 – Autenticação JWT + controle de acesso por org
"""
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext

from core.database import get_user_by_username, get_agent_by_api_key, update_user_last_login

SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
ALGORITHM = "HS256"
TOKEN_EXPIRE_H = int(os.getenv("TOKEN_EXPIRE_HOURS", "24"))
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer = HTTPBearer()

def hash_password(plain: str) -> str:
    return pwd_ctx.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)

def create_access_token(user_id: str, org_id: str, role: str) -> str:
    payload = {"sub": user_id, "org_id": org_id, "role": role, "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_H), "iat": datetime.utcnow()}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")

class CurrentUser:
    def __init__(self, user_id: str, org_id: str, role: str):
        self.user_id = user_id; self.org_id = org_id; self.role = role
    def require_role(self, *roles: str):
        if self.role not in roles: raise HTTPException(status_code=403, detail=f"Permissão insuficiente")

async def get_current_user(creds: HTTPAuthorizationCredentials = Security(bearer)) -> CurrentUser:
    payload = decode_token(creds.credentials)
    user_id = payload.get("sub"); org_id = payload.get("org_id"); role = payload.get("role", "viewer")
    if not user_id or not org_id: raise HTTPException(status_code=401)
    return CurrentUser(user_id=user_id, org_id=org_id, role=role)

def generate_agent_key() -> str:
    return f"s360_{secrets.token_urlsafe(36)}"

def require_admin(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    user.require_role("owner", "admin"); return user

def require_analyst(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    user.require_role("owner", "admin", "analyst"); return user
