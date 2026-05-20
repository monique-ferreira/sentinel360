import os
import certifi
from pymongo import MongoClient
from datetime import datetime

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
        _col("integration_configs").update_one(
            {"owner": owner, "provider": provider},
            {"$set": {**config, "owner": owner, "provider": provider,
                      "updated_at": datetime.now().isoformat()}},
            upsert=True,
        )
        return True
    except Exception as e:
        print(f"[ERRO DB] save_integration_config: {e}")
        return False


def get_integration_config(owner: str, provider: str) -> dict | None:
    try:
        return _col("integration_configs").find_one(
            {"owner": owner, "provider": provider}, {"_id": 0}
        )
    except Exception as e:
        print(f"[ERRO DB] get_integration_config: {e}")
        return None


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
