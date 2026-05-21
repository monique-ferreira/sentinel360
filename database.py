import base64
import os
import certifi
from pymongo import MongoClient
from datetime import datetime

# ── Field-level encryption for sensitive integration credentials ──────────────
# Requires ENCRYPTION_KEY env var (32 url-safe base64 bytes, generate with:
#   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
_ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
_fernet = None
if _ENCRYPTION_KEY:
    try:
        from cryptography.fernet import Fernet
        _fernet = Fernet(_ENCRYPTION_KEY.encode())
    except Exception as _e:
        print(f"[WARN DB] Fernet init failed: {_e} — credentials will be stored unencrypted")

_ENCRYPTED_FIELDS = {"client_secret", "access_token", "refresh_token"}


def _encrypt(value: str) -> str:
    if _fernet and isinstance(value, str):
        return "enc:" + _fernet.encrypt(value.encode()).decode()
    return value


def _decrypt(value: str) -> str:
    if _fernet and isinstance(value, str) and value.startswith("enc:"):
        return _fernet.decrypt(value[4:].encode()).decode()
    return value


def _encrypt_config(config: dict) -> dict:
    return {k: (_encrypt(v) if k in _ENCRYPTED_FIELDS else v) for k, v in config.items()}


def _decrypt_config(config: dict) -> dict:
    if not config:
        return config
    return {k: (_decrypt(v) if k in _ENCRYPTED_FIELDS and isinstance(v, str) else v)
            for k, v in config.items()}

MONGO_URI = os.environ.get("MONGO_URI")

try:
    client = MongoClient(MONGO_URI, tlsCAFile=certifi.where(), serverSelectionTimeoutMS=5000)
    db = client["sentinel360"]
    client.admin.command("ping")
    print("[DB] Conectado ao MongoDB Atlas.")
except Exception as e:
    print(f"[ERRO DB] Falha na conexão: {e}")
    db = None


def _col(name):
    if db is None:
        raise RuntimeError("Banco de dados indisponível.")
    return db[name]


# ── cloud scan results (isolados por usuário) ─────────────────────────────────

def save_cloud_results(owner: str, provider: str, results: list) -> bool:
    if not results:
        return False
    try:
        col = _col("cloud_results")
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for item in results:
            item["last_scan"]      = scan_date
            item["cloud_provider"] = provider
            item["owner"]          = owner
        col.delete_many({"owner": owner, "cloud_provider": provider})
        col.insert_many(results)
        _col("scan_history").insert_one({
            "owner":          owner,
            "data":           scan_date,
            "tipo":           f"cloud_{provider}",
            "total_arquivos": len(results),
            "inativos":       sum(1 for i in results if i.get("inativo") == "SIM"),
            "com_risco":      sum(1 for i in results if i.get("riscos") not in ("NENHUM", "")),
        })
        return True
    except Exception as e:
        print(f"[ERRO DB] save_cloud_results: {e}")
        return False


def get_cloud_results(owner: str, provider: str | None = None) -> list:
    try:
        query: dict = {"owner": owner}
        if provider:
            query["cloud_provider"] = provider
        return list(_col("cloud_results").find(query, {"_id": 0, "owner": 0}))
    except Exception as e:
        print(f"[ERRO DB] get_cloud_results: {e}")
        return []


def get_scan_history(owner: str) -> list:
    try:
        return list(
            _col("scan_history")
            .find({"owner": owner}, {"_id": 0, "owner": 0})
            .sort("data", -1)
            .limit(50)
        )
    except Exception as e:
        print(f"[ERRO DB] get_scan_history: {e}")
        return []


def delete_cloud_result(owner: str, caminho: str) -> bool:
    try:
        result = _col("cloud_results").delete_one({"owner": owner, "caminho": caminho})
        return result.deleted_count > 0
    except Exception as e:
        print(f"[ERRO DB] delete_cloud_result: {e}")
        return False


# ── VirusTotal cache ──────────────────────────────────────────────────────────

def get_vt_cache(sha256: str) -> dict | None:
    """Retorna resultado VT cacheado para o hash, ou None se não existir."""
    try:
        return _col("vt_cache").find_one({"sha256": sha256}, {"_id": 0})
    except Exception as e:
        print(f"[ERRO DB] get_vt_cache: {e}")
        return None


def set_vt_cache(sha256: str, result: dict) -> None:
    """Salva/atualiza resultado VT para o hash."""
    try:
        _col("vt_cache").update_one(
            {"sha256": sha256},
            {"$set": {**result, "sha256": sha256, "cached_at": datetime.utcnow().isoformat()}},
            upsert=True,
        )
    except Exception as e:
        print(f"[ERRO DB] set_vt_cache: {e}")


# ── users ─────────────────────────────────────────────────────────────────────

def find_user(username: str) -> dict | None:
    try:
        return _col("users").find_one({"username": username}, {"_id": 0})
    except Exception as e:
        print(f"[ERRO DB] find_user: {e}")
        return None


def find_user_by_email(email: str) -> dict | None:
    try:
        return _col("users").find_one({"email": email}, {"_id": 0})
    except Exception as e:
        print(f"[ERRO DB] find_user_by_email: {e}")
        return None


def create_user(user_data: dict) -> bool:
    try:
        _col("users").insert_one(user_data)
        return True
    except Exception as e:
        print(f"[ERRO DB] create_user: {e}")
        return False


# ── integration configs (isoladas por usuário) ────────────────────────────────

def save_integration_config(owner: str, provider: str, config: dict) -> bool:
    try:
        encrypted = _encrypt_config(config)
        _col("integration_configs").update_one(
            {"owner": owner, "provider": provider},
            {"$set": {**encrypted, "owner": owner, "provider": provider,
                      "updated_at": datetime.now().isoformat()}},
            upsert=True,
        )
        return True
    except Exception as e:
        print(f"[ERRO DB] save_integration_config: {e}")
        return False


def get_integration_config(owner: str, provider: str) -> dict | None:
    try:
        doc = _col("integration_configs").find_one(
            {"owner": owner, "provider": provider}, {"_id": 0}
        )
        return _decrypt_config(doc)
    except Exception as e:
        print(f"[ERRO DB] get_integration_config: {e}")
        return None


# ── user settings & profile ───────────────────────────────────────────────────

def get_user_settings(owner: str) -> dict:
    try:
        user = _col("users").find_one({"username": owner}, {"_id": 0, "password": 0})
        if not user:
            return {}
        return {
            "inactivity_days": user.get("inactivity_days", 180),
            "account_type":    user.get("account_type", "personal"),
            "org_id":          user.get("org_id"),
            "org_role":        user.get("org_role"),
            "org_status":      user.get("org_status"),
            "full_name":       user.get("full_name"),
            "email":           user.get("email"),
        }
    except Exception as e:
        print(f"[ERRO DB] get_user_settings: {e}")
        return {}


def update_user_settings(owner: str, updates: dict) -> bool:
    try:
        allowed = {"full_name", "email", "inactivity_days", "org_role"}
        safe = {k: v for k, v in updates.items() if k in allowed}
        if not safe:
            return False
        _col("users").update_one({"username": owner}, {"$set": safe})
        return True
    except Exception as e:
        print(f"[ERRO DB] update_user_settings: {e}")
        return False


# ── organizations ──────────────────────────────────────────────────────────────

def create_org(org_id: str, name: str, slug: str, admin_username: str) -> bool:
    try:
        _col("organizations").insert_one({
            "org_id":         org_id,
            "name":           name,
            "slug":           slug,
            "admin_username": admin_username,
            "created_at":     datetime.now().isoformat(),
        })
        return True
    except Exception as e:
        print(f"[ERRO DB] create_org: {e}")
        return False


def get_org_by_id(org_id: str) -> dict | None:
    try:
        return _col("organizations").find_one({"org_id": org_id}, {"_id": 0})
    except Exception as e:
        print(f"[ERRO DB] get_org_by_id: {e}")
        return None


def search_orgs(query: str) -> list[dict]:
    try:
        import re
        query = query[:50]  # cap length to prevent ReDoS
        pattern = re.compile(re.escape(query), re.IGNORECASE)
        orgs = list(_col("organizations").find(
            {"$or": [{"name": pattern}, {"slug": pattern}]},
            {"_id": 0, "org_id": 1, "name": 1, "slug": 1}
        ).limit(10))
        result = []
        for org in orgs:
            member_count = _col("org_join_requests").count_documents(
                {"org_id": org["org_id"], "status": "approved"}
            )
            result.append({**org, "member_count": member_count + 1})  # +1 for admin
        return result
    except Exception as e:
        print(f"[ERRO DB] search_orgs: {e}")
        return []


def create_join_request(org_id: str, username: str) -> bool:
    try:
        existing = _col("org_join_requests").find_one({"org_id": org_id, "username": username})
        if existing:
            _col("org_join_requests").update_one(
                {"org_id": org_id, "username": username},
                {"$set": {"status": "pending", "created_at": datetime.now().isoformat()}}
            )
        else:
            _col("org_join_requests").insert_one({
                "org_id":     org_id,
                "username":   username,
                "status":     "pending",
                "created_at": datetime.now().isoformat(),
            })
        return True
    except Exception as e:
        print(f"[ERRO DB] create_join_request: {e}")
        return False


def get_join_requests(org_id: str, status: str = "pending") -> list[dict]:
    try:
        return list(_col("org_join_requests").find(
            {"org_id": org_id, "status": status}, {"_id": 0}
        ))
    except Exception as e:
        print(f"[ERRO DB] get_join_requests: {e}")
        return []


def update_join_request(org_id: str, username: str, status: str) -> bool:
    try:
        _col("org_join_requests").update_one(
            {"org_id": org_id, "username": username},
            {"$set": {"status": status}}
        )
        if status == "approved":
            _col("users").update_one(
                {"username": username},
                {"$set": {"org_status": "approved"}}
            )
        return True
    except Exception as e:
        print(f"[ERRO DB] update_join_request: {e}")
        return False


def get_org_members(org_id: str) -> list[str]:
    try:
        org = get_org_by_id(org_id)
        admin = [org["admin_username"]] if org else []
        approved = [r["username"] for r in _col("org_join_requests").find(
            {"org_id": org_id, "status": "approved"}, {"username": 1}
        )]
        return admin + approved
    except Exception as e:
        print(f"[ERRO DB] get_org_members: {e}")
        return []


def get_workspace_data(org_id: str) -> dict:
    try:
        members = get_org_members(org_id)
        member_data = []
        for username in members:
            user = _col("users").find_one({"username": username}, {"_id": 0, "password": 0})
            results = list(_col("cloud_results").find({"owner": username}, {"_id": 0}))
            total_files   = len(results)
            inactive      = sum(1 for r in results if r.get("inativo") == "SIM")
            risky         = sum(1 for r in results if r.get("riscos") not in ("NENHUM", "", None))
            storage_mb    = sum(float(r.get("tamanho_mb") or 0) for r in results)
            member_data.append({
                "username":   username,
                "email":      user.get("email", "") if user else "",
                "full_name":  user.get("full_name", "") if user else "",
                "org_role":   "admin" if user and user.get("org_role") == "admin" else "member",
                "total_files":   total_files,
                "inactive_files": inactive,
                "risky_files":   risky,
                "storage_mb":    round(storage_mb, 2),
                "inactivity_days": user.get("inactivity_days", 180) if user else 180,
            })
        return {"members": member_data, "total_members": len(members)}
    except Exception as e:
        print(f"[ERRO DB] get_workspace_data: {e}")
        return {"members": [], "total_members": 0}


# ── activity logs ─────────────────────────────────────────────────────────────

def log_action(acao: str, detalhes: str, status: str = "OK", owner: str = "") -> None:
    try:
        _col("activity_logs").insert_one({
            "owner":    owner,
            "acao":     acao,
            "detalhes": detalhes,
            "status":   status,
            "data":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })
    except Exception as e:
        print(f"[ERRO DB] log_action: {e}")
