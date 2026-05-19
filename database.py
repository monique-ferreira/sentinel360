import os
import certifi
from pymongo import MongoClient, ASCENDING
from datetime import datetime

MONGO_URI = os.environ.get("MONGO_URI")

try:
    client = MongoClient(MONGO_URI, tlsCAFile=certifi.where(), serverSelectionTimeoutMS=5000)
    db = client["sentinel360"]
    client.admin.command("ping")
    print("[DB] Conectado ao MongoDB Atlas.")
except Exception as e:
    print(f"[ERRO DB] Falha na conexão: {e}")
    db = None  # servidor inicia mesmo sem banco

# ── coleções ──────────────────────────────────────────────────────────────────

def _col(name):
    if db is None:
        raise RuntimeError("Banco de dados indisponível.")
    return db[name]


# ── scan_results ──────────────────────────────────────────────────────────────

def save_scan_results(results: list) -> bool:
    if not results:
        return False
    try:
        col = _col("scan_results")
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for item in results:
            item["last_scan"] = scan_date
        col.delete_many({})
        col.insert_many(results)

        # salva resumo no histórico de scans
        _col("scan_history").insert_one({
            "data": scan_date,
            "total_arquivos": len(results),
            "inativos": sum(1 for i in results if i.get("inativo") == "SIM"),
            "com_risco": sum(1 for i in results if i.get("riscos") not in ("NENHUM", "")),
        })
        return True
    except Exception as e:
        print(f"[ERRO DB] save_scan_results: {e}")
        return False


def get_all_results() -> list:
    try:
        return list(_col("scan_results").find({}, {"_id": 0}))
    except Exception as e:
        print(f"[ERRO DB] get_all_results: {e}")
        return []


def delete_specific_file(path: str) -> bool:
    try:
        col = _col("scan_results")
        result = col.delete_one({"caminho": path})
        _col("activity_logs").insert_one({
            "acao": "REMOÇÃO",
            "caminho": path,
            "data": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "SUCESSO" if result.deleted_count > 0 else "NÃO ENCONTRADO",
        })
        return result.deleted_count > 0
    except Exception as e:
        print(f"[ERRO DB] delete_specific_file: {e}")
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


# ── integration configs ───────────────────────────────────────────────────────

def save_integration_config(provider: str, config: dict) -> bool:
    """
    Salva/atualiza credenciais de integração (ms365 | azure).
    Armazena apenas tenant_id e client_id em texto; client_secret
    não é recuperado pelo GET — fica opaco no banco.
    """
    try:
        _col("integration_configs").update_one(
            {"provider": provider},
            {"$set": {**config, "provider": provider, "updated_at": datetime.now().isoformat()}},
            upsert=True,
        )
        return True
    except Exception as e:
        print(f"[ERRO DB] save_integration_config: {e}")
        return False


def get_integration_config(provider: str) -> dict | None:
    try:
        doc = _col("integration_configs").find_one({"provider": provider}, {"_id": 0})
        return doc
    except Exception as e:
        print(f"[ERRO DB] get_integration_config: {e}")
        return None


# ── activity logs ─────────────────────────────────────────────────────────────

def log_action(acao: str, detalhes: str, status: str = "OK") -> None:
    try:
        _col("activity_logs").insert_one({
            "acao": acao,
            "detalhes": detalhes,
            "status": status,
            "data": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })
    except Exception as e:
        print(f"[ERRO DB] log_action: {e}")
