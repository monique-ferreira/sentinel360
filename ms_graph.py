"""
ms_graph.py — Integração com Microsoft Graph API

Funções:
  Autenticação:  _get_token, test_credentials
  Usuários:      audit_inactive_users_azure, audit_inactive_users_ms365
  Arquivos cloud: scan_sharepoint_files, scan_onedrive_files
  Utilitários:   _days_since, _graph_get, _graph_get_single, _download_content
"""

from __future__ import annotations

import re
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

# ── Padrões de risco (mesmo conjunto do scanner local) ────────────────────────

SENSITIVE_PATTERNS: dict[str, str] = {
    "Credencial": (
        r"(?i)(password|passwd|senha|pwd|secret|api_key|apikey|access_key|token)"
        r"\s*[=:\"']+\s*[^\s\"']{6,}"
    ),
    "Chave Privada": (
        r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP|PRIVATE)\s+KEY(?: BLOCK)?-----"
    ),
    "Token/Key": (
        r"(?:"
        r"AKIA[0-9A-Z]{16}"
        r"|(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}"
        r"|sk-[A-Za-z0-9]{20,}"
        r"|xoxb-[0-9A-Za-z\-]+"
        r"|AIza[0-9A-Za-z\-_]{35}"
        r"|[0-9a-f]{32,64}(?=\s|$|[\"'])"
        r")"
    ),
    "CPF":  r"\b\d{3}[.\-]?\d{3}[.\-]?\d{3}[-]?\d{2}\b",
    "CNPJ": r"\b\d{2}[.\-]?\d{3}[.\-]?\d{3}[\/]?\d{4}[-]?\d{2}\b",
    "Email": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    "Connection String": (
        r"(?i)(mongodb(\+srv)?://|mysql://|postgres(ql)?://|mssql://)[^\s\"'<>]+"
    ),
}

TEXT_EXT = {
    ".txt", ".log", ".conf", ".cfg", ".ini", ".py", ".js", ".ts",
    ".json", ".sql", ".env", ".xml", ".yaml", ".yml", ".toml",
    ".sh", ".bash", ".ps1", ".bat", ".cmd", ".csv", ".md",
    ".html", ".htm", ".php", ".rb", ".go", ".properties",
}

SENSITIVE_FILENAMES = re.compile(
    r"(?i)(password|passwd|credentials|secrets?|private[_\-]?key"
    r"|\.env|id_rsa|id_dsa|id_ecdsa|id_ed25519|\.pem|\.p12|\.pfx"
    r"|htpasswd|shadow|config\.ini|secrets\.json)",
    re.IGNORECASE,
)

MAX_FILE_BYTES = 8192   # bytes lidos de cada arquivo de texto
MAX_FILES_PER_SCAN = 5000  # limite de segurança para scans grandes


# ── Autenticação ───────────────────────────────────────────────────────────────

def _get_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    if not _MSAL_AVAILABLE:
        raise RuntimeError("msal não instalado. Execute: pip install msal")
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    app = msal.ConfidentialClientApplication(
        client_id, authority=authority, client_credential=client_secret,
    )
    result = app.acquire_token_for_client(
        scopes=["https://graph.microsoft.com/.default"]
    )
    if "access_token" not in result:
        error = result.get("error_description") or result.get("error") or str(result)
        raise ValueError(f"Falha na autenticação Microsoft: {error}")
    return result["access_token"]


# ── Helpers HTTP ───────────────────────────────────────────────────────────────

def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Accept": "application/json"}


def _graph_get(token: str, url: str, params: dict | None = None) -> dict:
    """GET paginado — retorna todos os valores de todas as páginas."""
    all_values: list = []
    next_url: Optional[str] = url
    h = _headers(token)
    while next_url:
        resp = requests.get(next_url, headers=h, params=params, timeout=30)
        params = None
        if resp.status_code == 429:
            retry = int(resp.headers.get("Retry-After", "5"))
            time.sleep(retry)
            continue
        resp.raise_for_status()
        data = resp.json()
        all_values.extend(data.get("value", []))
        next_url = data.get("@odata.nextLink")
    return {"value": all_values}


def _graph_get_single(token: str, url: str) -> dict:
    resp = requests.get(url, headers=_headers(token), timeout=30)
    resp.raise_for_status()
    return resp.json()


def _download_content(token: str, download_url: str) -> str:
    """Baixa os primeiros MAX_FILE_BYTES do arquivo e retorna como texto."""
    try:
        resp = requests.get(
            download_url,
            headers={"Authorization": f"Bearer {token}"},
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


# ── Helpers de data ────────────────────────────────────────────────────────────

def _days_since(iso_date: Optional[str]) -> int:
    if not iso_date:
        return -1
    try:
        dt = datetime.fromisoformat(iso_date.rstrip("Z")).replace(tzinfo=timezone.utc)
        return (datetime.now(tz=timezone.utc) - dt).days
    except Exception:
        return -1


# ── Análise de arquivo individual ─────────────────────────────────────────────

def _analyze_item(
    token: str,
    item: dict,
    site_name: str,
    drive_name: str,
    days_threshold: int,
) -> dict | None:
    """
    Analisa um item do SharePoint/OneDrive.
    Retorna dict de resultado ou None se não for relevante.
    Usa lastAccessedDateTime se disponível, senão lastModifiedDateTime.
    """
    name = item.get("name", "")
    size = item.get("size", 0)
    web_url = item.get("webUrl", "")
    # Prefer lastAccessedDateTime (actual use), fall back to lastModifiedDateTime
    file_info = item.get("file", {}) or {}
    last_accessed = (
        item.get("lastAccessedDateTime")
        or file_info.get("lastAccessedDateTime")
        or item.get("lastModifiedDateTime", "")
    )
    days_ago = _days_since(last_accessed)
    is_inactive = days_ago >= days_threshold if days_ago >= 0 else False

    risks: list[str] = []

    # Detecta pelo nome
    if SENSITIVE_FILENAMES.search(name):
        risks.append("Credencial")

    # Detecta pelo conteúdo (só arquivos de texto e razoável tamanho)
    ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
    download_url = item.get("@microsoft.graph.downloadUrl") or (
        item.get("file", {}).get("downloadUrl") if item.get("file") else None
    )
    if ext in TEXT_EXT and 0 < size <= 2 * 1024 * 1024 and download_url:
        content = _download_content(token, download_url)
        for label, pattern in SENSITIVE_PATTERNS.items():
            if re.search(pattern, content) and label not in risks:
                risks.append(label)

    if not is_inactive and not risks:
        return None

    return {
        "nome":       name,
        "caminho":    web_url,
        "origem":     f"SharePoint — {site_name}/{drive_name}",
        "inativo":    "SIM" if is_inactive else "NÃO",
        "riscos":     ", ".join(risks) if risks else "NENHUM",
        "tamanho_mb": round(size / (1024 * 1024), 3),
        "last_scan":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "dias_sem_acesso": days_ago,
        "ultimo_acesso":   last_accessed[:10] if last_accessed else "",
        "graph_item_id":   item.get("id", ""),
        "graph_drive_id":  item.get("parentReference", {}).get("driveId", ""),
    }


def _walk_drive(
    token: str,
    drive_id: str,
    item_id: str,
    site_name: str,
    drive_name: str,
    days_threshold: int,
    results: list,
    counter: list,  # [int] — mutable counter
    progress_cb=None,  # Callable[[int], None] | None — called after each file
) -> None:
    """Percorre recursivamente uma pasta do drive e analisa arquivos."""
    if counter[0] >= MAX_FILES_PER_SCAN:
        return
    url = f"{GRAPH_BASE}/drives/{drive_id}/items/{item_id}/children"
    try:
        data = _graph_get(token, url)
    except Exception as e:
        print(f"[GRAPH] Erro ao listar pasta {item_id}: {e}")
        return

    for item in data.get("value", []):
        if counter[0] >= MAX_FILES_PER_SCAN:
            break
        if "folder" in item:
            _walk_drive(
                token, drive_id, item["id"],
                site_name, drive_name, days_threshold, results, counter, progress_cb,
            )
        elif "file" in item:
            counter[0] += 1
            result = _analyze_item(token, item, site_name, drive_name, days_threshold)
            if result:
                results.append(result)
            if progress_cb:
                progress_cb(counter[0])


# ── Varredura SharePoint ───────────────────────────────────────────────────────

def scan_sharepoint_files(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    days_threshold: int = 180,
    state_ref=None,
    progress_cb=None,
) -> list[dict]:
    """
    Varre todos os sites SharePoint da organização.

    Permissões necessárias:
      Sites.Read.All · Files.Read.All

    Args:
        days_threshold: Arquivos sem modificação há N dias são marcados inativos.
        state_ref:      Objeto opcional com .progress, .processed_files, .total_files
                        para atualização de progresso em tempo real.

    Returns:
        Lista de dicts compatível com o schema de resultados locais, com campo
        "origem" indicando "SharePoint — Site/Drive".
    """
    token = _get_token(tenant_id, client_id, client_secret)
    results: list[dict] = []
    counter = [0]

    # 1. Listar todos os sites
    print("[GRAPH] Listando sites SharePoint...")
    try:
        sites_data = _graph_get(token, f"{GRAPH_BASE}/sites?search=*")
        sites = sites_data.get("value", [])
    except Exception as e:
        raise RuntimeError(f"Erro ao listar sites SharePoint: {e}")

    print(f"[GRAPH] {len(sites)} site(s) encontrado(s).")

    for si, site in enumerate(sites):
        if counter[0] >= MAX_FILES_PER_SCAN:
            print(f"[GRAPH] Limite de {MAX_FILES_PER_SCAN} arquivos atingido.")
            break

        site_id   = site["id"]
        site_name = site.get("displayName") or site.get("name") or site_id

        # 2. Listar drives (bibliotecas de documentos) do site
        try:
            drives_data = _graph_get(token, f"{GRAPH_BASE}/sites/{site_id}/drives")
            drives = drives_data.get("value", [])
        except Exception as e:
            print(f"[GRAPH] Erro ao listar drives de {site_name}: {e}")
            continue

        for drive in drives:
            if counter[0] >= MAX_FILES_PER_SCAN:
                break
            drive_id   = drive["id"]
            drive_name = drive.get("name", drive_id)
            print(f"[GRAPH] Varrendo: {site_name}/{drive_name} ...")
            _walk_drive(
                token, drive_id, "root",
                site_name, drive_name, days_threshold, results, counter, progress_cb,
            )

        if state_ref is not None:
            state_ref.progress = round((si + 1) / len(sites) * 100, 1)

    print(f"[GRAPH] SharePoint scan concluído. {len(results)} itens relevantes de {counter[0]} arquivos varridos.")
    return results


# ── Varredura OneDrive (todos os usuários) ────────────────────────────────────

def scan_onedrive_files(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    days_threshold: int = 180,
    max_users: int = 50,
    progress_cb=None,
) -> list[dict]:
    """
    Varre o OneDrive for Business de cada usuário da organização.

    Permissões necessárias:
      User.Read.All · Files.Read.All

    Args:
        max_users: Limite de usuários varridos (evita scans excessivamente longos).

    Returns:
        Lista de dicts com campo "origem": "OneDrive — <email>".
    """
    token = _get_token(tenant_id, client_id, client_secret)
    results: list[dict] = []
    counter = [0]

    users_data = _graph_get(
        token,
        f"{GRAPH_BASE}/users?$select=id,displayName,mail,userPrincipalName&$top=999",
    )
    users = users_data.get("value", [])[:max_users]
    print(f"[GRAPH] OneDrive scan: {len(users)} usuário(s).")

    for user in users:
        if counter[0] >= MAX_FILES_PER_SCAN:
            break
        uid   = user["id"]
        email = user.get("mail") or user.get("userPrincipalName", uid)
        try:
            drive_resp = _graph_get_single(token, f"{GRAPH_BASE}/users/{uid}/drive")
            drive_id   = drive_resp["id"]
        except Exception:
            continue

        _walk_drive(token, drive_id, "root", "OneDrive", email, days_threshold, results, counter, progress_cb)

    print(f"[GRAPH] OneDrive scan concluído. {len(results)} itens relevantes.")
    return results


# ── Varredura OneDrive pessoal (token delegado) ───────────────────────────────

def scan_onedrive_personal(access_token: str, days_threshold: int = 180, progress_cb=None) -> list[dict]:
    """
    Varre o OneDrive do usuário autenticado via token delegado.
    Não requer admin consent — acessa apenas os arquivos do próprio usuário.
    """
    results: list[dict] = []
    counter = [0]
    try:
        drive_resp = _graph_get_single(access_token, f"{GRAPH_BASE}/me/drive")
        drive_id = drive_resp["id"]
        _walk_drive(access_token, drive_id, "root", "OneDrive Pessoal", "Meus Arquivos", days_threshold, results, counter, progress_cb)
    except Exception as e:
        print(f"[GRAPH] Erro ao varrer OneDrive pessoal: {e}")
    print(f"[GRAPH] OneDrive pessoal: {len(results)} itens relevantes de {counter[0]} arquivos.")
    return results


# ── Deleção de arquivo via Graph API ─────────────────────────────────────────

def delete_drive_item(access_token: str, drive_id: str, item_id: str) -> None:
    """
    Deleta um arquivo do OneDrive/SharePoint via Graph API.
    Requer scope Files.ReadWrite (personal) ou Files.ReadWrite.All (corporativo).
    Lança exceção se falhar.
    """
    import requests as _req
    url = f"{GRAPH_BASE}/drives/{drive_id}/items/{item_id}"
    resp = _req.delete(url, headers={"Authorization": f"Bearer {access_token}"})
    if resp.status_code not in (200, 204):
        raise Exception(f"Graph API retornou {resp.status_code}: {resp.text[:200]}")


# ── Auditoria de usuários ─────────────────────────────────────────────────────

def audit_inactive_users_azure(
    tenant_id: str, client_id: str, client_secret: str, inactive_days: int = 90,
) -> list[dict]:
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
        days_i = _days_since(sign_in.get("lastSignInDateTime"))
        days_n = _days_since(sign_in.get("lastNonInteractiveSignInDateTime"))
        days_ago = min(d for d in (days_i, days_n) if d >= 0) if any(d >= 0 for d in (days_i, days_n)) else -1
        if days_ago == -1 or days_ago >= inactive_days:
            inactive.append({
                "display_name":    user.get("displayName") or user.get("userPrincipalName", ""),
                "email":           user.get("mail") or user.get("userPrincipalName", ""),
                "days_inactive":   days_ago,
                "account_enabled": user.get("accountEnabled", True),
            })
    return inactive


def audit_inactive_users_ms365(
    tenant_id: str, client_id: str, client_secret: str, inactive_days: int = 90,
) -> list[dict]:
    token = _get_token(tenant_id, client_id, client_secret)
    url = (
        f"{GRAPH_BASE}/users"
        "?$select=displayName,mail,userPrincipalName,accountEnabled,signInActivity,assignedLicenses"
        "&$top=999"
    )
    data = _graph_get(token, url)
    inactive: list[dict] = []
    for user in data["value"]:
        sign_in  = user.get("signInActivity") or {}
        days_ago = _days_since(sign_in.get("lastSignInDateTime"))
        if days_ago == -1 or days_ago >= inactive_days:
            inactive.append({
                "display_name":    user.get("displayName") or user.get("userPrincipalName", ""),
                "email":           user.get("mail") or user.get("userPrincipalName", ""),
                "days_inactive":   days_ago,
                "account_enabled": user.get("accountEnabled", True),
            })
    return inactive


# ── Teste de credenciais ──────────────────────────────────────────────────────

def test_credentials(tenant_id: str, client_id: str, client_secret: str) -> dict:
    try:
        token = _get_token(tenant_id, client_id, client_secret)
        resp  = requests.get(
            f"{GRAPH_BASE}/organization",
            headers=_headers(token), timeout=15,
        )
        resp.raise_for_status()
        orgs     = resp.json().get("value", [])
        org_name = orgs[0].get("displayName", "Desconhecido") if orgs else "Desconhecido"
        return {"ok": True, "org_name": org_name}
    except Exception as e:
        return {"ok": False, "error": str(e)}
