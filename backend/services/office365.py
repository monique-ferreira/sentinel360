"""
Sentinel360 - Microsoft Graph API Integration
"""
from __future__ import annotations
import httpx
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

async def get_access_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(url, data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default",
        })
        resp.raise_for_status()
        return resp.json()["access_token"]


class GraphClient:
    """Async client for Microsoft Graph API."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None

    async def _get_headers(self) -> dict:
        if not self._token or (self._token_expiry and datetime.utcnow() >= self._token_expiry):
            self._token = await get_access_token(self.tenant_id, self.client_id, self.client_secret)
            self._token_expiry = datetime.utcnow() + timedelta(minutes=55)
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    async def _get(self, path: str, params: dict = None) -> dict:
        headers = await self._get_headers()
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(f"{GRAPH_BASE}{path}", headers=headers, params=params)
            resp.raise_for_status()
            return resp.json()

    async def _get_paged(self, path: str, params: dict = None, max_pages: int = 10) -> List[dict]:
        results = []
        data = await self._get(path, params)
        results.extend(data.get("value", []))
        page = 1
        while "@odata.nextLink" in data and page < max_pages:
            headers = await self._get_headers()
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(data["@odata.nextLink"], headers=headers)
                resp.raise_for_status()
                data = resp.json()
            results.extend(data.get("value", []))
            page += 1
        return results

    async def get_inactive_users(self, days: int = 90) -> List[dict]:
        threshold = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        users = await self._get_paged("/users", params={
            "$select": "id,displayName,userPrincipalName,signInActivity,accountEnabled,createdDateTime",
            "$filter": "accountEnabled eq true",
            "$top": "999",
        })
        inactive = []
        for u in users:
            sign_in = u.get("signInActivity") or {}
            last = sign_in.get("lastSignInDateTime")
            if not last or last < threshold:
                inactive.append({
                    "id": u["id"],
                    "display_name": u.get("displayName", ""),
                    "email": u.get("userPrincipalName", ""),
                    "last_signin": last,
                    "account_enabled": u.get("accountEnabled", True),
                    "days_inactive": days if not last else _days_since(last),
                })
        return inactive

    async def get_all_users(self) -> List[dict]:
        users = await self._get_paged("/users", params={
            "$select": "id,displayName,userPrincipalName,accountEnabled,department,jobTitle",
            "$top": "999",
        })
        return [{"id": u["id"], "name": u.get("displayName"), "email": u.get("userPrincipalName"),
                 "enabled": u.get("accountEnabled"), "department": u.get("department"),
                 "job_title": u.get("jobTitle")} for u in users]

    async def full_audit(self, inactive_days: int = 90) -> dict:
        import asyncio
        inactive_users, all_users = await asyncio.gather(
            self.get_inactive_users(inactive_days),
            self.get_all_users(),
        )
        return {
            "total_users": len(all_users),
            "inactive_users": inactive_users,
            "inactive_count": len(inactive_users),
            "audited_at": datetime.utcnow().isoformat(),
            "inactive_threshold": inactive_days,
        }


def _days_since(iso_date: str) -> int:
    try:
        dt = datetime.fromisoformat(iso_date.replace("Z", "+00:00"))
        return (datetime.utcnow() - dt.replace(tzinfo=None)).days
    except Exception:
        return -1
