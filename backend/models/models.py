"""
Sentinel360 - Data Models (MongoDB / Pydantic)
Multi-tenant: Organization -> User -> Agent -> Scan -> Result -> Alert
"""
from __future__ import annotations
from datetime import datetime
from typing import Optional, List
from enum import Enum
from pydantic import BaseModel, Field, EmailStr
from bson import ObjectId


class PyObjectId(str):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate
    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return str(v)


class UserRole(str, Enum):
    OWNER = "owner"; ADMIN = "admin"; ANALYST = "analyst"; VIEWER = "viewer"

class AgentStatus(str, Enum):
    ONLINE = "online"; OFFLINE = "offline"; SCANNING = "scanning"; ERROR = "error"

class RiskLevel(str, Enum):
    CRITICAL = "critical"; HIGH = "high"; MEDIUM = "medium"; LOW = "low"; NONE = "none"

class ScanStatus(str, Enum):
    PENDING = "pending"; RUNNING = "running"; COMPLETED = "completed"; FAILED = "failed"


class Organization(BaseModel):
    id: Optional[PyObjectId] = Field(default=None, alias="_id")
    name: str
    slug: str
    plan: str = "free"
    max_agents: int = 5
    max_users: int = 10
    office365_tenant_id: Optional[str] = None
    office365_client_id: Optional[str] = None
    webhook_url: Optional[str] = None
    alert_email: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = True
    class Config:
        populate_by_name = True; json_encoders = {ObjectId: str}


class User(BaseModel):
    id: Optional[PyObjectId] = Field(default=None, alias="_id")
    org_id: str
    email: EmailStr
    username: str
    hashed_password: str
    full_name: Optional[str] = None
    role: UserRole = UserRole.ANALYST
    is_active: bool = True
    last_login: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    class Config:
        populate_by_name = True; json_encoders = {ObjectId: str}


class Agent(BaseModel):
    id: Optional[PyObjectId] = Field(default=None, alias="_id")
    org_id: str
    name: str
    hostname: str
    platform: str
    agent_version: str
    api_key: str
    status: AgentStatus = AgentStatus.OFFLINE
    last_seen: Optional[datetime] = None
    last_scan_at: Optional[datetime] = None
    ip_address: Optional[str] = None
    tags: List[str] = []
    created_at: datetime = Field(default_factory=datetime.utcnow)
    class Config:
        populate_by_name = True; json_encoders = {ObjectId: str}


class Scan(BaseModel):
    id: Optional[PyObjectId] = Field(default=None, alias="_id")
    org_id: str
    agent_id: str
    triggered_by: str
    status: ScanStatus = ScanStatus.PENDING
    days_threshold: int = 180
    progress: float = 0.0
    total_files: int = 0
    processed_files: int = 0
    results_count: int = 0
    risk_count: int = 0
    inactive_count: int = 0
    storage_mb: float = 0.0
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error_message: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    class Config:
        populate_by_name = True; json_encoders = {ObjectId: str}


class RiskDetail(BaseModel):
    type: str
    confidence: float
    snippet: Optional[str] = None
    detected_by: str = "regex"


class ScanResult(BaseModel):
    id: Optional[PyObjectId] = Field(default=None, alias="_id")
    org_id: str
    scan_id: str
    agent_id: str
    name: str
    path: str
    extension: str
    size_mb: float
    last_accessed: datetime
    last_modified: datetime
    is_inactive: bool
    risk_level: RiskLevel = RiskLevel.NONE
    risks: List[RiskDetail] = []
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    class Config:
        populate_by_name = True; json_encoders = {ObjectId: str}


class Alert(BaseModel):
    id: Optional[PyObjectId] = Field(default=None, alias="_id")
    org_id: str
    scan_id: str
    result_id: str
    risk_level: RiskLevel
    title: str
    description: str
    file_path: str
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    class Config:
        populate_by_name = True; json_encoders = {ObjectId: str}
