"""
google_drive.py — Integração com Google Drive API v3

Funções:
  OAuth (delegado/pessoal): get_auth_url, exchange_code, refresh_access_token
  OAuth (service account/workspace): get_service_token
  Arquivos: scan_drive_files
"""

from __future__ import annotations

import hashlib
import re
import time
from datetime import datetime, timezone
from typing import Optional, Callable

import requests

from ms_graph import SENSITIVE_PATTERNS, SENSITIVE_FILENAMES, TEXT_EXT, ARCHIVE_EXT, MAX_FILE_BYTES, MAX_FILES_PER_SCAN

DRIVE_BASE  = "https://www.googleapis.com/drive/v3"
TOKEN_URL   = "https://oauth2.googleapis.com/token"
AUTH_URL    = "https://accounts.google.com/o/oauth2/v2/auth"
REVOKE_URL  = "https://oauth2.googleapis.com/revoke"

SCOPES_PERSONAL  = "https://www.googleapis.com/auth/drive.readonly https://www.googleapis.com/auth/userinfo.email openid"
SCOPES_WORKSPACE = "https://www.googleapis.com/auth/drive.readonly"


# ── OAuth helpers ─────────────────────────────────────────────────────────────

def get_auth_url(client_id: str, redirect_uri: str, state: str, workspace: bool = False) -> str:
    import urllib.parse
    scopes = SCOPES_WORKSPACE if workspace else SCOPES_PERSONAL
    params = {
        "client_id":     client_id,
        "redirect_uri":  redirect_uri,
        "response_type": "code",
        "scope":         scopes,
        "access_type":   "offline",
        "prompt":        "consent select_account",
        "state":         state,
    }
    return f"{AUTH_URL}?{urllib.parse.urlencode(params)}"


def exchange_code(client_id: str, client_secret: str, redirect_uri: str, code: str) -> dict:
    """Troca authorization code por access_token + refresh_token."""
    resp = requests.post(TOKEN_URL, data={
        "code":          code,
        "client_id":     client_id,
        "client_secret": client_secret,
        "redirect_uri":  redirect_uri,
        "grant_type":    "authorization_code",
    }, timeout=15)
    resp.raise_for_status()
    return resp.json()


def refresh_access_token(client_id: str, client_secret: str, refresh_token: str) -> str:
    """Obtém novo access_token via refresh_token."""
    resp = requests.post(TOKEN_URL, data={
        "client_id":     client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
        "grant_type":    "refresh_token",
    }, timeout=15)
    resp.raise_for_status()
    return resp.json()["access_token"]


def get_user_info(access_token: str) -> dict:
    resp = requests.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def test_service_account(service_account_json: dict) -> dict:
    """Valida service account credentials (Workspace)."""
    try:
        import google.oauth2.service_account as sa
        import google.auth.transport.requests as gtr
        creds = sa.Credentials.from_service_account_info(
            service_account_json,
            scopes=["https://www.googleapis.com/auth/drive.readonly"],
        )
        creds.refresh(gtr.Request())
        return {"ok": True, "token": creds.token}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── Drive API helpers ─────────────────────────────────────────────────────────

def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _drive_get_all(token: str, url: str, params: dict) -> list[dict]:
    """Pagina sobre todos os resultados de uma query do Drive API."""
    results = []
    next_page = None
    while True:
        p = {**params}
        if next_page:
            p["pageToken"] = next_page
        resp = requests.get(url, headers=_headers(token), params=p, timeout=30)
        if resp.status_code == 429:
            time.sleep(int(resp.headers.get("Retry-After", "5")))
            continue
        resp.raise_for_status()
        data = resp.json()
        results.extend(data.get("files", []))
        next_page = data.get("nextPageToken")
        if not next_page:
            break
    return results


def _download_content(token: str, file_id: str) -> str:
    """Baixa primeiros MAX_FILE_BYTES de um arquivo de texto do Drive."""
    try:
        resp = requests.get(
            f"{DRIVE_BASE}/files/{file_id}?alt=media",
            headers=_headers(token),
            timeout=20,
            stream=True,
        )
        resp.raise_for_status()
        raw = b""
        for chunk in resp.iter_content(chunk_size=MAX_FILE_BYTES):
            raw += chunk
            if len(raw) >= MAX_FILE_BYTES:
                break
        return raw[:MAX_FILE_BYTES].decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _sha256_of_content(token: str, file_id: str, md5_from_api: str) -> str:
    """
    Google Drive fornece md5Checksum, não SHA256.
    Para VirusTotal precisamos SHA256 — baixamos o conteúdo e calculamos.
    Limitamos a 5MB para não explodir a memória.
    """
    try:
        resp = requests.get(
            f"{DRIVE_BASE}/files/{file_id}?alt=media",
            headers=_headers(token),
            timeout=30,
            stream=True,
        )
        resp.raise_for_status()
        MAX = 5 * 1024 * 1024
        raw = b""
        for chunk in resp.iter_content(chunk_size=65536):
            raw += chunk
            if len(raw) >= MAX:
                break
        return hashlib.sha256(raw).hexdigest()
    except Exception:
        return ""


def _days_since(iso_date: Optional[str]) -> int:
    if not iso_date:
        return -1
    try:
        dt = datetime.fromisoformat(iso_date.rstrip("Z")).replace(tzinfo=timezone.utc)
        return (datetime.now(tz=timezone.utc) - dt).days
    except Exception:
        return -1


# ── Análise de arquivo individual ─────────────────────────────────────────────

def _analyze_file(
    token: str,
    f: dict,
    days_threshold: int,
    compute_sha256: bool = False,
) -> dict | None:
    name      = f.get("name", "")
    size      = int(f.get("size", 0) or 0)
    mime      = f.get("mimeType", "")
    web_url   = f.get("webViewLink", "")
    file_id   = f.get("id", "")
    modified  = f.get("modifiedTime", "")
    viewed    = f.get("viewedByMeTime") or modified  # best proxy for last access

    # Skip Google-native files (Docs, Sheets, Slides) — they have no binary size
    if mime.startswith("application/vnd.google-apps"):
        return None

    days_ago    = _days_since(viewed)
    is_inactive = days_ago >= days_threshold if days_ago >= 0 else False

    risks: list[str] = []

    if SENSITIVE_FILENAMES.search(name):
        risks.append("Credencial")

    ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext in TEXT_EXT and 0 < size <= 2 * 1024 * 1024:
        content = _download_content(token, file_id)
        for label, pattern in SENSITIVE_PATTERNS.items():
            if re.search(pattern, content) and label not in risks:
                risks.append(label)

    if ext in ARCHIVE_EXT and "Arquivo compactado" not in risks:
        risks.append("Arquivo compactado")

    if not is_inactive and not risks:
        return None

    sha256 = ""
    if compute_sha256 and size <= 5 * 1024 * 1024:
        sha256 = _sha256_of_content(token, file_id, f.get("md5Checksum", ""))

    return {
        "nome":            name,
        "caminho":         web_url,
        "origem":          "Google Drive",
        "inativo":         "SIM" if is_inactive else "NÃO",
        "riscos":          ", ".join(risks) if risks else "NENHUM",
        "tamanho_mb":      round(size / (1024 * 1024), 3),
        "last_scan":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "dias_sem_acesso": days_ago,
        "ultimo_acesso":   viewed[:10] if viewed else "",
        "graph_item_id":   file_id,   # reuse field name for compat with FileViewerModal
        "graph_drive_id":  "gdrive",
        "sha256":          sha256,
        "gdrive_file_id":  file_id,
    }


# ── Scanner principal ─────────────────────────────────────────────────────────

def scan_drive_files(
    access_token: str,
    days_threshold: int = 180,
    progress_cb: Callable[[int], None] | None = None,
    shared_drives: bool = True,
) -> list[dict]:
    """
    Lista e analisa todos os arquivos do Google Drive acessíveis pelo token.
    Inclui Meu Drive + Drives Compartilhados (Workspace).
    """
    results: list[dict] = []
    counter = [0]

    fields = "nextPageToken,files(id,name,mimeType,size,modifiedTime,viewedByMeTime,webViewLink,md5Checksum,parents)"

    # ── Meu Drive ────────────────────────────────────────────────────────────
    files = _drive_get_all(access_token, f"{DRIVE_BASE}/files", {
        "q":        "trashed=false",
        "fields":   fields,
        "pageSize": 1000,
        "spaces":   "drive",
    })

    for f in files:
        if counter[0] >= MAX_FILES_PER_SCAN:
            break
        result = _analyze_file(access_token, f, days_threshold)
        if result:
            results.append(result)
        counter[0] += 1
        if progress_cb:
            progress_cb(counter[0])

    # ── Shared Drives (Workspace) ────────────────────────────────────────────
    if shared_drives:
        try:
            drives_resp = requests.get(
                f"{DRIVE_BASE}/drives",
                headers=_headers(access_token),
                params={"pageSize": 100, "fields": "drives(id,name)"},
                timeout=15,
            )
            if drives_resp.ok:
                for drive in drives_resp.json().get("drives", []):
                    drive_id   = drive["id"]
                    drive_name = drive.get("name", drive_id)
                    drive_files = _drive_get_all(access_token, f"{DRIVE_BASE}/files", {
                        "q":              f"trashed=false",
                        "fields":         fields,
                        "pageSize":       1000,
                        "spaces":         "drive",
                        "driveId":        drive_id,
                        "includeItemsFromAllDrives": True,
                        "supportsAllDrives": True,
                        "corpora":        "drive",
                    })
                    for f in drive_files:
                        if counter[0] >= MAX_FILES_PER_SCAN:
                            break
                        result = _analyze_file(access_token, f, days_threshold)
                        if result:
                            result["origem"] = f"Google Drive — {drive_name}"
                            results.append(result)
                        counter[0] += 1
                        if progress_cb:
                            progress_cb(counter[0])
        except Exception:
            pass  # Shared Drives might not be available on personal accounts

    return results
