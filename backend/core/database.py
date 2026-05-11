"""
Sentinel360 - Database Layer (MongoDB)
Multi-tenant support via org_id in all queries
"""
import os
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING, DESCENDING
from bson import ObjectId
from typing import Optional, List, Dict, Any
from datetime import datetime

MONGO_URL = os.getenv("MONGO_URL") or os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME  = os.getenv("DB_NAME", "sentinel360")

client: Optional[AsyncIOMotorClient] = None

def get_db():
    return client[DB_NAME]

async def connect_db():
    global client
    client = AsyncIOMotorClient(MONGO_URL)
    await _create_indexes(get_db())
    print(f"[DB] Connected: {MONGO_URL}/{DB_NAME}")

async def disconnect_db():
    if client:
        client.close()

async def _create_indexes(db):
    await db.organizations.create_index([("slug", ASCENDING)], unique=True)
    await db.users.create_index([("email", ASCENDING), ("org_id", ASCENDING)], unique=True)
    await db.users.create_index([("org_id", ASCENDING)])
    await db.agents.create_index([("api_key", ASCENDING)], unique=True)
    await db.agents.create_index([("org_id", ASCENDING)])
    await db.scans.create_index([("org_id", ASCENDING), ("created_at", DESCENDING)])
    await db.scan_results.create_index([("org_id", ASCENDING), ("scan_id", ASCENDING), ("risk_level", ASCENDING)])
    await db.scan_results.create_index([("org_id", ASCENDING), ("is_inactive", ASCENDING)])
    await db.alerts.create_index([("org_id", ASCENDING), ("acknowledged", ASCENDING)])
    print("[DB] Indexes created.")


def _oid(id_str: str) -> ObjectId:
    return ObjectId(id_str)

def _serialize(doc: dict) -> dict:
    if doc is None:
        return None
    for k, v in doc.items():
        if isinstance(v, ObjectId):
            doc[k] = str(v)
        elif isinstance(v, dict):
            doc[k] = _serialize(v)
        elif isinstance(v, list):
            doc[k] = [_serialize(i) if isinstance(i, dict) else str(i) if isinstance(i, ObjectId) else i for i in v]
    return doc


# Organizations
async def create_org(data: dict) -> dict:
    db = get_db(); result = await db.organizations.insert_one(data); data["_id"] = str(result.inserted_id); return data

async def get_org(org_id: str) -> Optional[dict]:
    db = get_db(); doc = await db.organizations.find_one({"_id": _oid(org_id)}); return _serialize(doc)

async def get_org_by_slug(slug: str) -> Optional[dict]:
    db = get_db(); doc = await db.organizations.find_one({"slug": slug}); return _serialize(doc)

async def update_org(org_id: str, data: dict) -> bool:
    db = get_db(); res = await db.organizations.update_one({"_id": _oid(org_id)}, {"$set": data}); return res.modified_count > 0


# Users
async def create_user(data: dict) -> dict:
    db = get_db(); result = await db.users.insert_one(data); data["_id"] = str(result.inserted_id); return data

async def get_user_by_email(email: str, org_id: str) -> Optional[dict]:
    db = get_db(); doc = await db.users.find_one({"email": email, "org_id": org_id}); return _serialize(doc)

async def get_user_by_username(username: str) -> Optional[dict]:
    db = get_db(); doc = await db.users.find_one({"username": username}); return _serialize(doc)

async def get_users_by_org(org_id: str) -> List[dict]:
    db = get_db(); cursor = db.users.find({"org_id": org_id, "is_active": True}); return [_serialize(d) async for d in cursor]

async def update_user_last_login(user_id: str):
    db = get_db(); await db.users.update_one({"_id": _oid(user_id)}, {"$set": {"last_login": datetime.utcnow()}})


# Agents
async def create_agent(data: dict) -> dict:
    db = get_db(); result = await db.agents.insert_one(data); data["_id"] = str(result.inserted_id); return data

async def get_agent_by_api_key(api_key: str) -> Optional[dict]:
    db = get_db(); doc = await db.agents.find_one({"api_key": api_key}); return _serialize(doc)

async def get_agents_by_org(org_id: str) -> List[dict]:
    db = get_db(); cursor = db.agents.find({"org_id": org_id}); return [_serialize(d) async for d in cursor]

async def update_agent_status(agent_id: str, status: str, ip: str = None):
    db = get_db()
    update = {"status": status, "last_seen": datetime.utcnow()}
    if ip: update["ip_address"] = ip
    await db.agents.update_one({"_id": _oid(agent_id)}, {"$set": update})


# Scans
async def create_scan(data: dict) -> dict:
    db = get_db(); result = await db.scans.insert_one(data); data["_id"] = str(result.inserted_id); return data

async def update_scan(scan_id: str, data: dict):
    db = get_db(); await db.scans.update_one({"_id": _oid(scan_id)}, {"$set": data})

async def get_scan(scan_id: str) -> Optional[dict]:
    db = get_db(); doc = await db.scans.find_one({"_id": _oid(scan_id)}); return _serialize(doc)

async def get_scans_by_org(org_id: str, limit: int = 20) -> List[dict]:
    db = get_db(); cursor = db.scans.find({"org_id": org_id}).sort("created_at", DESCENDING).limit(limit); return [_serialize(d) async for d in cursor]


# Results
async def bulk_insert_results(results: List[dict]) -> int:
    if not results: return 0
    db = get_db(); res = await db.scan_results.insert_many(results); return len(res.inserted_ids)

async def get_results(org_id: str, scan_id: str = None, risk_level: str = None, only_inactive: bool = False, skip: int = 0, limit: int = 100) -> List[dict]:
    db = get_db()
    query: Dict[str, Any] = {"org_id": org_id}
    if scan_id: query["scan_id"] = scan_id
    if risk_level: query["risk_level"] = risk_level
    if only_inactive: query["is_inactive"] = True
    cursor = db.scan_results.find(query).sort("detected_at", DESCENDING).skip(skip).limit(limit)
    return [_serialize(d) async for d in cursor]

async def get_dashboard_stats(org_id: str) -> dict:
    db = get_db()
    pipeline = [
        {"$match": {"org_id": org_id}},
        {"$group": {
            "_id": None,
            "total": {"$sum": 1},
            "inactive": {"$sum": {"$cond": ["$is_inactive", 1, 0]}},
            "critical": {"$sum": {"$cond": [{"$eq": ["$risk_level", "critical"]}, 1, 0]}},
            "high": {"$sum": {"$cond": [{"$eq": ["$risk_level", "high"]}, 1, 0]}},
            "medium": {"$sum": {"$cond": [{"$eq": ["$risk_level", "medium"]}, 1, 0]}},
            "storage_mb": {"$sum": "$size_mb"},
        }}
    ]
    docs = await db.scan_results.aggregate(pipeline).to_list(1)
    if not docs: return {"total": 0, "inactive": 0, "critical": 0, "high": 0, "medium": 0, "storage_mb": 0}
    d = docs[0]; d.pop("_id", None); return d


# Alerts
async def create_alert(data: dict) -> dict:
    db = get_db(); result = await db.alerts.insert_one(data); data["_id"] = str(result.inserted_id); return data

async def get_alerts(org_id: str, only_open: bool = True, limit: int = 50) -> List[dict]:
    db = get_db()
    query: Dict[str, Any] = {"org_id": org_id}
    if only_open: query["acknowledged"] = False
    cursor = db.alerts.find(query).sort("created_at", DESCENDING).limit(limit)
    return [_serialize(d) async for d in cursor]

async def acknowledge_alert(alert_id: str, user_id: str) -> bool:
    db = get_db()
    res = await db.alerts.update_one(
        {"_id": _oid(alert_id)},
        {"$set": {"acknowledged": True, "acknowledged_by": user_id, "acknowledged_at": datetime.utcnow()}}
    )
    return res.modified_count > 0
