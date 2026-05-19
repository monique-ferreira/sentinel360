"""
ms_graph.py — Integração com Microsoft Graph API

Usado por:
  - Microsoft 365 (Exchange, SharePoint, Teams): auditoria de emails, arquivos externos
  - Azure Active Directory: usuários inativos, contas sem MFA, grupos de segurança

Requisitos:
  - pip install msal requests
  - App Registration no Azure Portal com as permissões configuradas
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Optional

import requests

try:
    import msal
    _MSAL_AVAILABLE = True
except ImportError:
    _MSAL_AVAILABLE = False


GRAPH_BASE = "https://graph.microsoft.com/v1.0"
AUTHORITY  = "https://login.microsoftonline.com/{tenant_id}"


# ── Autenticação ───────────────────────────────────────────────────────────────

def _get_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Obtém access token via Client Credentials Flow (sem usuário interativo)."""
    if not _MSAL_AVAILABLE:
        raise RuntimeError("msal não instalado. Execute: pip install msal")

    authority = AUTHORITY.format(tenant_id=tenant_id)
    app = msal.ConfidentialClientApplication(
        client_id,
        authority=authority,
        client_credential=client_secret,
    )
    result = app.acquire_token_for_client(
        scopes=["https://graph.microsoft.com/.default"]
    )
    if "access_token" not in result:
        error = result.get("error_description") or result.get("error") or str(result)
        raise ValueError(f"Falha na autenticação Microsoft: {error}")
    return result["access_token"]


def _graph_get(token: str, url: str, params: dict | None = None) -> dict:
    """Faz GET paginado no Microsoft Graph e retorna todos os valores."""
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    all_values = []
    next_url: Optional[str] = url

    while next_url:
        resp = requests.get(next_url, headers=headers, params=params, timeout=30)
        params = None  # só usa params na primeira chamada
        resp.raise_for_status()
        data = resp.json()
        all_values.extend(data.get("value", []))
        next_url = data.get("@odata.nextLink")

    return {"value": all_values}


# ── Helpers de data ────────────────────────────────────────────────────────────

def _days_since(iso_date: Optional[str]) -> int:
    """Retorna dias desde uma data ISO 8601, ou -1 se null."""
    if not iso_date:
        return -1
    try:
        dt = datetime.fromisoformat(iso_date.rstrip("Z")).replace(tzinfo=timezone.utc)
        return (datetime.now(tz=timezone.utc) - dt).days
    except Exception:
        return -1


# ── Azure Active Directory ─────────────────────────────────────────────────────

def audit_inactive_users_azure(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    inactive_days: int = 90,
) -> list[dict]:
    """
    Retorna usuários do Azure AD cujo último login é anterior a `inactive_days`.

    Permissões necessárias no App Registration:
      - User.Read.All
      - AuditLog.Read.All   (para signInActivity — requer Azure AD P1/P2)
      - Directory.Read.All

    Args:
        tenant_id: Directory (tenant) ID do Azure AD.
        client_id: Application (client) ID do App Registration.
        client_secret: Segredo gerado no App Registration.
        inactive_days: Limiar de inatividade em dias.

    Returns:
        Lista de dicts com: display_name, email, days_inactive, account_enabled.
    """
    token = _get_token(tenant_id, client_id, client_secret)

    url = (
        f"{GRAPH_BASE}/users"
        "?$select=displayName,mail,userPrincipalName,accountEnabled,signInActivity"
        "&$top=999"
    )
    data = _graph_get(token, url)

    inactive: list[dict] = []
    for user in data["value"]:
        sign_in = user.get("signInActivity") or {}
        last_interactive = sign_in.get("lastSignInDateTime")
        last_non_interactive = sign_in.get("lastNonInteractiveSignInDateTime")

        # Usa o mais recente entre os dois tipos de login
        days_int = _days_since(last_interactive)
        days_non = _days_since(last_non_interactive)
        days_ago = min(
            d for d in (days_int, days_non) if d >= 0
        ) if any(d >= 0 for d in (days_int, days_non)) else -1

        if days_ago == -1 or days_ago >= inactive_days:
            inactive.append({
                "display_name":    user.get("displayName") or user.get("userPrincipalName", ""),
                "email":           user.get("mail") or user.get("userPrincipalName", ""),
                "days_inactive":   days_ago,
                "account_enabled": user.get("accountEnabled", True),
            })

    return inactive


# ── Microsoft 365 ─────────────────────────────────────────────────────────────

def audit_inactive_users_ms365(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    inactive_days: int = 90,
) -> list[dict]:
    """
    Audita usuários inativos do Microsoft 365 (Exchange/SharePoint).

    Usa o mesmo endpoint de signInActivity do Graph, mas com foco em
    licenciados para Exchange / SharePoint.

    Permissões necessárias:
      - User.Read.All
      - AuditLog.Read.All
      - Mail.Read (para auditoria de Exchange)
      - Sites.Read.All (para auditoria de SharePoint)

    Returns:
        Lista de dicts com: display_name, email, days_inactive, licenses.
    """
    token = _get_token(tenant_id, client_id, client_secret)

    url = (
        f"{GRAPH_BASE}/users"
        "?$select=displayName,mail,userPrincipalName,accountEnabled"
        ",signInActivity,assignedLicenses"
        "&$top=999"
    )
    data = _graph_get(token, url)

    # SKUs que indicam licença Microsoft 365
    M365_SKUS = {
        "6fd2c87f-b296-42f0-b197-1e91e994b900",  # Office 365 E3
        "c7df2760-2c81-4ef7-b578-5b5392b571df",  # Office 365 E5
        "18181a46-0d4e-45cd-891e-60aabd171b4e",  # Office 365 Business Essentials
        "f30db892-07e9-47e9-837c-80727f46fd3d",  # Microsoft 365 Business Basic
        "cbdc14ab-d96c-4c30-b9f4-6ada7cdc1d46",  # Microsoft 365 Business Premium
    }

    inactive: list[dict] = []
    for user in data["value"]:
        # Filtra apenas usuários com licença M365 (opcional — descomente se quiser filtrar)
        # licenses = [l.get("skuId") for l in user.get("assignedLicenses", [])]
        # if not any(s in M365_SKUS for s in licenses):
        #     continue

        sign_in = user.get("signInActivity") or {}
        last_sign_in = sign_in.get("lastSignInDateTime")
        days_ago = _days_since(last_sign_in)

        if days_ago == -1 or days_ago >= inactive_days:
            inactive.append({
                "display_name":  user.get("displayName") or user.get("userPrincipalName", ""),
                "email":         user.get("mail") or user.get("userPrincipalName", ""),
                "days_inactive": days_ago,
                "account_enabled": user.get("accountEnabled", True),
            })

    return inactive


# ── Verificação de credenciais (teste de conectividade) ───────────────────────

def test_credentials(tenant_id: str, client_id: str, client_secret: str) -> dict:
    """
    Testa se as credenciais são válidas obtendo o token e consultando a organização.

    Returns:
        {"ok": True, "org_name": "..."} ou {"ok": False, "error": "..."}
    """
    try:
        token = _get_token(tenant_id, client_id, client_secret)
        resp = requests.get(
            f"{GRAPH_BASE}/organization",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        resp.raise_for_status()
        orgs = resp.json().get("value", [])
        org_name = orgs[0].get("displayName", "Desconhecido") if orgs else "Desconhecido"
        return {"ok": True, "org_name": org_name}
    except Exception as e:
        return {"ok": False, "error": str(e)}
