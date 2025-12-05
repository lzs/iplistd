# iplistd - main.py
from fastapi import FastAPI, HTTPException, Depends, Query, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, validator
from datetime import datetime, timedelta
from typing import List, Optional
import ipaddress
import uvicorn
import hashlib
import hmac
import secrets
import os
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
import atexit
import json

# Configuration constants at the top of your file
MIN_IPV4_PREFIX_LENGTH = 24  # Disallow subnets larger than /24
MIN_IPV6_PREFIX_LENGTH = 64  # Disallow IPv6 subnets larger than /64

# Database setup
DATABASE_URL = "sqlite:///./ip_filter.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Add configuration constants
EXPORT_INTERVAL_MINUTES = int(os.getenv("EXPORT_INTERVAL_MINUTES", "5"))
AUTO_EXPORT_ENABLED = os.getenv("AUTO_EXPORT_ENABLED", "true").lower() == "true"
EXPIRED_RETENTION_MINUTES = int(os.getenv("EXPIRED_RETENTION_MINUTES", str(7 * 24 * 60)))  # Default 1 week
OUTPUT_FILE_PATH = os.getenv("OUTPUT_FILE_PATH", "/tmp/ip_filters.txt")  # Change this path as needed

# Authentication setup
security = HTTPBearer()

# Database model for API keys
class APIKeyDB(Base):
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, index=True)
    key_name = Column(String, unique=True, index=True)
    key_hash = Column(String, index=True)  # Store hashed version for security
    permissions = Column(String)  # JSON string of permissions list
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    description = Column(String, nullable=True)

# Database model for IP filter list
class IPFilterDB(Base):
    __tablename__ = "ip_filters"
    
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, index=True)
    timeout_minutes = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    is_active = Column(Boolean, default=True)
    reason = Column(String, nullable=True)
    api_key_id = Column(Integer, nullable=True, index=True)  # Store which API key was used

# Create tables
Base.metadata.create_all(bind=engine)

# Pydantic models
class IPFilterCreate(BaseModel):
    ip_address: str
    timeout_minutes: int
    reason: Optional[str] = None
    
    @validator('ip_address')
    def validate_ip_address(cls, v):
        try:
            # Validate if it's a valid IP address or CIDR notation
            network = ipaddress.ip_network(v, strict=False)
            
            # Check if it's a subnet and if the prefix length is acceptable
            if '/' in v:
                prefix_length = network.prefixlen
                
                if network.version == 4:
                    if prefix_length < MIN_IPV4_PREFIX_LENGTH:
                        raise ValueError(
                            f'IPv4 subnet /{prefix_length} not allowed. '
                            f'Minimum prefix length is /{MIN_IPV4_PREFIX_LENGTH}'
                        )
                elif network.version == 6:
                    if prefix_length < MIN_IPV6_PREFIX_LENGTH:
                        raise ValueError(
                            f'IPv6 subnet /{prefix_length} not allowed. '
                            f'Minimum prefix length is /{MIN_IPV6_PREFIX_LENGTH}'
                        )
            
            return v
        except ValueError as e:
            if "not allowed" in str(e):
                raise e
            else:
                raise ValueError('Invalid IP address or CIDR notation')
    
    @validator('timeout_minutes')
    def validate_timeout(cls, v):
        if v <= 0:
            raise ValueError('Timeout must be greater than 0')
        if v > 525600:  # 1 year in minutes
            raise ValueError('Timeout cannot exceed 1 year')
        return v

class IPFilterResponse(BaseModel):
    id: int
    ip_address: str
    timeout_minutes: int
    created_at: datetime
    expires_at: datetime
    is_active: bool
    reason: Optional[str] = None
    api_key_id: Optional[int] = None
    
    class Config:
        from_attributes = True

class IPFilterUpdate(BaseModel):
    timeout_minutes: Optional[int] = None
    reason: Optional[str] = None
    is_active: Optional[bool] = None

class ExportResponse(BaseModel):
    message: str
    file_path: str
    record_count: int
    export_time: datetime

class APIKeyCreate(BaseModel):
    key_name: str
    permissions: List[str]
    description: Optional[str] = None

class APIKeyResponse(BaseModel):
    id: int
    key_name: str
    permissions: List[str]
    created_at: datetime
    last_used: Optional[datetime] = None
    is_active: bool
    description: Optional[str] = None
    
    class Config:
        from_attributes = True

class APIKeyCreateResponse(BaseModel):
    key_name: str
    api_key: str
    permissions: List[str]
    description: Optional[str] = None
    message: str

# FastAPI app
app = FastAPI(
    title="IP Filter Management API",
    description="API for managing IP address filter lists with timeout functionality and authentication",
    version="1.0.0"
)

# Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Helper function to clean expired entries
def cleanup_expired_entries(db: Session):
    """
    Clean up expired entries in two phases:
    1. Mark entries as inactive when they expire
    2. Delete entries that have been inactive for the retention period
    """
    current_time = datetime.utcnow()
    
    # Phase 1: Mark expired entries as inactive
    newly_expired = db.query(IPFilterDB).filter(
        IPFilterDB.expires_at <= current_time,
        IPFilterDB.is_active == True
    ).all()
    
    for entry in newly_expired:
        entry.is_active = False
    
    # Phase 2: Delete entries that have been inactive beyond retention period
    retention_cutoff = current_time - timedelta(minutes=EXPIRED_RETENTION_MINUTES)
    
    old_expired_entries = db.query(IPFilterDB).filter(
        IPFilterDB.is_active == False,
        IPFilterDB.expires_at <= retention_cutoff
    ).all()
    
    deleted_count = len(old_expired_entries)
    for entry in old_expired_entries:
        db.delete(entry)
    
    db.commit()
    
    return {
        "newly_expired": len(newly_expired),
        "deleted": deleted_count
    }

# Helper function to export active IPs to text file
def export_active_ips_to_file(db: Session, file_path: str = OUTPUT_FILE_PATH) -> int:
    """Export all active (non-expired) IP addresses to a flat text file."""
    cleanup_expired_entries(db)
    
    active_filters = db.query(IPFilterDB).filter(
        IPFilterDB.is_active == True,
        IPFilterDB.expires_at > datetime.utcnow()
    ).all()
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    with open(file_path, 'w') as f:
        #f.write(f"# IP Filter Export - Generated on {datetime.utcnow()}\n")
        #f.write(f"# Format: IP_ADDRESS (expires: YYYY-MM-DD HH:MM:SS) - REASON\n")
        #f.write("#\n")
        
        for ip_filter in active_filters:
            #reason = f" - {ip_filter.reason}" if ip_filter.reason else ""
            f.write(f"{ip_filter.ip_address}\n")
    
    return len(active_filters)

# Add this after your existing imports and before the database setup
scheduler = AsyncIOScheduler()

# Modify your existing export function to be async
async def auto_export_and_cleanup():
    """Automatically export active IPs and cleanup expired entries."""
    db = SessionLocal()
    try:
        # Clean up expired entries
        cleanup_result = cleanup_expired_entries(db)
        
        # Export active IPs to file
        record_count = export_active_ips_to_file(db, OUTPUT_FILE_PATH)
        
        print(f"Auto-export completed: {record_count} active IPs exported, {cleanup_result['newly_expired']} newly expired, {cleanup_result['deleted']} old entries deleted")
        return {
            "exported": record_count, 
            "newly_expired": cleanup_result['newly_expired'],
            "deleted": cleanup_result['deleted']
        }
    
    except Exception as e:
        print(f"Auto-export failed: {e}")
        return {"error": str(e)}
    finally:
        db.close()

# Add startup and shutdown event handlers
@app.on_event("startup")
async def startup_event():
    """Start the background scheduler when the app starts."""
    # Create default API keys if they don't exist
    db = SessionLocal()
    try:
        create_default_api_keys(db)
    finally:
        db.close()
    
    # Log configuration at startup
    log_configuration()
    
    if AUTO_EXPORT_ENABLED:
        scheduler.add_job(
            auto_export_and_cleanup,
            IntervalTrigger(minutes=EXPORT_INTERVAL_MINUTES),
            id='auto_export_cleanup',
            name='Auto export and cleanup',
            replace_existing=True
        )
        scheduler.start()
        print(f"✓ Background scheduler started - auto-export every {EXPORT_INTERVAL_MINUTES} minutes")
    else:
        print("⚠ Auto-export is disabled")
    
    # Log file path accessibility
    try:
        os.makedirs(os.path.dirname(OUTPUT_FILE_PATH), exist_ok=True)
        print(f"✓ Output directory is accessible: {os.path.dirname(OUTPUT_FILE_PATH)}")
    except Exception as e:
        print(f"⚠ Warning: Cannot access output directory: {e}")

@app.on_event("shutdown")
async def shutdown_event():
    """Stop the scheduler when the app shuts down."""
    scheduler.shutdown()
    print("Background scheduler stopped")

# Authentication functions
def hash_api_key(api_key: str) -> str:
    """Hash an API key for secure storage."""
    return hashlib.sha256(api_key.encode()).hexdigest()

def generate_api_key(prefix: str = "sk") -> str:
    """Generate a new API key."""
    random_part = secrets.token_hex(16)
    return f"{prefix}_{random_part}"

def create_default_api_keys(db: Session):
    """Create default API keys if they don't exist."""
    default_keys = [
        {
            "key_name": "admin",
            "permissions": ["read", "write", "delete", "admin"],
            "description": "Administrator key with full access"
        },
        {
            "key_name": "appn", 
            "permissions": ["read", "write"],
            "description": "Application key for read/write operations"
        },
        {
            "key_name": "readonly",
            "permissions": ["read"],
            "description": "Read-only access key"
        }
    ]
    
    created_keys = []
    for key_data in default_keys:
        # Check if key already exists
        existing = db.query(APIKeyDB).filter(APIKeyDB.key_name == key_data["key_name"]).first()
        if not existing:
            # Generate new API key
            api_key = generate_api_key(key_data["key_name"])
            key_hash = hash_api_key(api_key)
            
            db_key = APIKeyDB(
                key_name=key_data["key_name"],
                key_hash=key_hash,
                permissions=json.dumps(key_data["permissions"]),
                description=key_data["description"]
            )
            db.add(db_key)
            created_keys.append({
                "key_name": key_data["key_name"],
                "api_key": api_key,
                "permissions": key_data["permissions"]
            })
    
    if created_keys:
        db.commit()
        print("=" * 60)
        print("NEW API KEYS CREATED - SAVE THESE SECURELY!")
        print("=" * 60)
        for key_info in created_keys:
            print(f"Key Name: {key_info['key_name']}")
            print(f"API Key:  {key_info['api_key']}")
            print(f"Permissions: {key_info['permissions']}")
            print("-" * 40)
        print("=" * 60)

def verify_api_key_from_db(db: Session, token: str) -> dict:
    """Verify API key against database."""
    token_hash = hash_api_key(token)
    
    api_key_record = db.query(APIKeyDB).filter(
        APIKeyDB.key_hash == token_hash,
        APIKeyDB.is_active == True
    ).first()
    
    if not api_key_record:
        return None
    
    # Update last used timestamp
    api_key_record.last_used = datetime.utcnow()
    db.commit()
    
    return {
        "key_name": api_key_record.key_name,
        "permissions": json.loads(api_key_record.permissions),
        "description": api_key_record.description
    }

# Modified authentication functions
def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(security)) -> dict:
    """Verify API key and return user info with permissions."""
    token = credentials.credentials
    
    # Get database session
    db = SessionLocal()
    try:
        user_info = verify_api_key_from_db(db, token)
        if not user_info:
            raise HTTPException(
                status_code=401,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user_info
    finally:
        db.close()

def require_permission(required_permission: str):
    """Decorator to require specific permissions."""
    def permission_check(user_info: dict = Depends(verify_api_key)):
        if required_permission not in user_info["permissions"]:
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions. Required: {required_permission}"
            )
        return user_info
    return permission_check

# API Endpoints

@app.get("/admin/api-keys", response_model=List[APIKeyResponse])
async def list_api_keys(
    db: Session = Depends(get_db),
    user_info: dict = Depends(require_permission("admin"))
):
    """List all API keys (without revealing the actual keys). Requires 'admin' permission."""
    api_keys = db.query(APIKeyDB).all()
    
    result = []
    for key in api_keys:
        result.append(APIKeyResponse(
            id=key.id,
            key_name=key.key_name,
            permissions=json.loads(key.permissions),
            created_at=key.created_at,
            last_used=key.last_used,
            is_active=key.is_active,
            description=key.description
        ))
    
    return result

# Add API key management endpoints
@app.post("/admin/api-keys", response_model=APIKeyCreateResponse)
async def create_api_key(
    api_key_data: APIKeyCreate,
    db: Session = Depends(get_db),
    user_info: dict = Depends(require_permission("admin"))
):
    """Create a new API key. Requires 'admin' permission."""
    # Check if key name already exists
    existing = db.query(APIKeyDB).filter(APIKeyDB.key_name == api_key_data.key_name).first()
    if existing:
        raise HTTPException(status_code=400, detail="API key name already exists")
    
    # Validate permissions
    valid_permissions = ["read", "write", "delete", "admin"]
    for perm in api_key_data.permissions:
        if perm not in valid_permissions:
            raise HTTPException(status_code=400, detail=f"Invalid permission: {perm}")
    
    # Generate new API key
    api_key = generate_api_key(api_key_data.key_name)
    key_hash = hash_api_key(api_key)
    
    db_key = APIKeyDB(
        key_name=api_key_data.key_name,
        key_hash=key_hash,
        permissions=json.dumps(api_key_data.permissions),
        description=api_key_data.description
    )
    
    db.add(db_key)
    db.commit()
    
    return APIKeyCreateResponse(
        key_name=api_key_data.key_name,
        api_key=api_key,
        permissions=api_key_data.permissions,
        description=api_key_data.description,
        message="API key created successfully. Save this key securely - it won't be shown again!"
    )

@app.put("/admin/api-keys/{key_name}")
async def update_api_key(
    key_name: str,
    is_active: bool,
    db: Session = Depends(get_db),
    user_info: dict = Depends(require_permission("admin"))
):
    """Enable or disable an API key. Requires 'admin' permission."""
    api_key = db.query(APIKeyDB).filter(APIKeyDB.key_name == key_name).first()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    api_key.is_active = is_active
    db.commit()
    
    status = "enabled" if is_active else "disabled"
    return {"message": f"API key '{key_name}' has been {status}"}

@app.delete("/admin/api-keys/{key_name}")
async def delete_api_key(
    key_name: str,
    db: Session = Depends(get_db),
    user_info: dict = Depends(require_permission("admin"))
):
    """Delete an API key. Requires 'admin' permission."""
    # Prevent deletion of current user's key
    if user_info["key_name"] == key_name:
        raise HTTPException(status_code=400, detail="Cannot delete your own API key")
    
    api_key = db.query(APIKeyDB).filter(APIKeyDB.key_name == key_name).first()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    db.delete(api_key)
    db.commit()
    
    return {"message": f"API key '{key_name}' has been deleted"}

@app.get("/")
async def root():
    return {
        "message": "IP Filter Management API",
        "version": "1.0.0",
        "docs": "/docs",
        "authentication": "Bearer token required"
    }

# Add a manual trigger endpoint
@app.post("/ip-filters/auto-export")
async def trigger_auto_export(
    user_info: dict = Depends(require_permission("write"))
):
    """Manually trigger auto-export and cleanup."""
    result = await auto_export_and_cleanup()
    return {
        "message": "Auto-export and cleanup completed",
        "result": result,
        "timestamp": datetime.utcnow()
    }

@app.post("/ip-filters/", response_model=IPFilterResponse, status_code=201)
async def add_ip_filter(
    ip_filter: IPFilterCreate,
    db: Session = Depends(get_db),
    user_info: dict = Depends(require_permission("write"))
):
    """
    Add an IP address to the filter list with a timeout value.
    Requires 'write' permission.
    """
    # Check if IP already exists and is active
    existing = db.query(IPFilterDB).filter(
        IPFilterDB.ip_address == ip_filter.ip_address,
        IPFilterDB.is_active == True
    ).first()

    api_key_id = user_info.get("api_key_id") if user_info else None

    if existing:
        existing.timeout_minutes = ip_filter.timeout_minutes
        existing.expires_at = datetime.utcnow() + timedelta(minutes=ip_filter.timeout_minutes)
        existing.reason = ip_filter.reason or existing.reason
        existing.created_at = datetime.utcnow()
        existing.api_key_id = api_key_id
        db.commit()
        db.refresh(existing)
        return existing

    expires_at = datetime.utcnow() + timedelta(minutes=ip_filter.timeout_minutes)

    db_ip_filter = IPFilterDB(
        ip_address=ip_filter.ip_address,
        timeout_minutes=ip_filter.timeout_minutes,
        expires_at=expires_at,
        reason=ip_filter.reason,
        api_key_id=api_key_id
    )

    db.add(db_ip_filter)
    db.commit()
    db.refresh(db_ip_filter)
    export_active_ips_to_file(db)

    return db_ip_filter

@app.get("/ip-filters/", response_model=List[IPFilterResponse])
async def get_ip_filters(
    active_only: bool = Query(True, description="Return only active (non-expired) filters"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of records to return"),
    db: Session = Depends(get_db),
    user_info: dict = Depends(require_permission("read"))
):
    """
    Retrieve IP filters from the database.
    Requires 'read' permission.
    """
    cleanup_expired_entries(db)
    
    query = db.query(IPFilterDB)
    
    if active_only:
        query = query.filter(IPFilterDB.is_active == True)
    
    ip_filters = query.offset(skip).limit(limit).all()
    return ip_filters

@app.get("/ip-filters/{filter_id}", response_model=IPFilterResponse)
async def get_ip_filter(
    filter_id: int,
    db: Session = Depends(get_db),
    user_info: dict = Depends(require_permission("read"))
):
    """Get a specific IP filter by ID. Requires 'read' permission."""
    ip_filter = db.query(IPFilterDB).filter(IPFilterDB.id == filter_id).first()
    
    if not ip_filter:
        raise HTTPException(status_code=404, detail="IP filter not found")
    
    return ip_filter

@app.put("/ip-filters/{filter_id}", response_model=IPFilterResponse)
async def update_ip_filter(
    filter_id: int,
    ip_filter_update: IPFilterUpdate,
    db: Session = Depends(get_db),
    user_info: dict = Depends(require_permission("write"))
):
    """Update an existing IP filter. Requires 'write' permission."""
    ip_filter = db.query(IPFilterDB).filter(IPFilterDB.id == filter_id).first()
    
    if not ip_filter:
        raise HTTPException(status_code=404, detail="IP filter not found")
    
    if ip_filter_update.timeout_minutes is not None:
        ip_filter.timeout_minutes = ip_filter_update.timeout_minutes
        ip_filter.expires_at = datetime.utcnow() + timedelta(minutes=ip_filter_update.timeout_minutes)

    if ip_filter_update.reason is not None:
        ip_filter.reason = ip_filter_update.reason

    if ip_filter_update.is_active is not None:
        ip_filter.is_active = ip_filter_update.is_active

    # Record which API key performed the update
    api_key_id = user_info.get("api_key_id") if user_info else None
    if api_key_id is not None:
        ip_filter.api_key_id = api_key_id

    db.commit()
    db.refresh(ip_filter)

    return ip_filter

@app.delete("/ip-filters/{filter_id}")
async def delete_ip_filter(
    filter_id: int,
    db: Session = Depends(get_db),
    user_info: dict = Depends(require_permission("delete"))
):
    """Delete (deactivate) an IP filter. Requires 'delete' permission."""
    ip_filter = db.query(IPFilterDB).filter(IPFilterDB.id == filter_id).first()
    
    if not ip_filter:
        raise HTTPException(status_code=404, detail="IP filter not found")
    
    ip_filter.is_active = False
    db.commit()
    
    return {"message": f"IP filter {filter_id} has been deactivated"}

@app.get("/ip-filters/check/{ip_address}")
async def check_ip_filter(
    ip_address: str,
    db: Session = Depends(get_db),
    user_info: dict = Depends(require_permission("read"))
):
    """
    Check if an IP address is currently filtered.
    Requires 'read' permission.
    """
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")
    
    cleanup_expired_entries(db)
    
    # Check for exact match
    exact_match = db.query(IPFilterDB).filter(
        IPFilterDB.ip_address == ip_address,
        IPFilterDB.is_active == True
    ).first()
    
    if exact_match:
        return {
            "is_filtered": True,
            "match_type": "exact",
            "filter": IPFilterResponse.model_validate(exact_match)
        }
    
    # Check for CIDR matches
    active_filters = db.query(IPFilterDB).filter(
        IPFilterDB.is_active == True
    ).all()
    
    target_ip = ipaddress.ip_address(ip_address)
    
    for ip_filter in active_filters:
        try:
            network = ipaddress.ip_network(ip_filter.ip_address, strict=False)
            if target_ip in network:
                return {
                    "is_filtered": True,
                    "match_type": "cidr",
                    "filter": IPFilterResponse.model_validate(ip_filter)
                }
        except ValueError:
            continue
    
    return {
        "is_filtered": False,
        "match_type": None,
        "filter": None
    }

@app.post("/ip-filters/export", response_model=ExportResponse)
async def export_ip_filters_to_file(
    file_path: Optional[str] = Query(None, description="Custom file path for export"),
    db: Session = Depends(get_db),
    user_info: dict = Depends(require_permission("read"))
):
    """
    Export all active IP filters to a flat text file.
    Requires 'read' permission.
    """
    export_path = file_path or OUTPUT_FILE_PATH
    record_count = export_active_ips_to_file(db, export_path)
    
    return ExportResponse(
        message=f"Successfully exported {record_count} active IP filters",
        file_path=export_path,
        record_count=record_count,
        export_time=datetime.utcnow()
    )

@app.post("/ip-filters/cleanup")
async def cleanup_expired_filters(
    db: Session = Depends(get_db),
    user_info: dict = Depends(require_permission("write"))
):
    """Manually trigger cleanup of expired IP filters. Requires 'write' permission."""
    cleanup_result = cleanup_expired_entries(db)
    return {
        "message": f"Cleanup completed: {cleanup_result['newly_expired']} newly expired, {cleanup_result['deleted']} old entries deleted",
        "newly_expired": cleanup_result['newly_expired'],
        "deleted": cleanup_result['deleted'],
        "retention_period_minutes": EXPIRED_RETENTION_MINUTES
    }

@app.get("/ip-filters/stats/summary")
async def get_filter_stats(
    db: Session = Depends(get_db),
    user_info: dict = Depends(require_permission("read"))
):
    """Get statistics about IP filters. Requires 'read' permission."""
    current_time = datetime.utcnow()
    retention_cutoff = current_time - timedelta(minutes=EXPIRED_RETENTION_MINUTES)
    
    total_filters = db.query(IPFilterDB).count()
    active_filters = db.query(IPFilterDB).filter(IPFilterDB.is_active == True).count()
    
    # Count recently expired (within retention period)
    recently_expired = db.query(IPFilterDB).filter(
        IPFilterDB.is_active == False,
        IPFilterDB.expires_at > retention_cutoff
    ).count()
    
    # Count currently expired but still active (shouldn't happen after cleanup)
    currently_expired_active = db.query(IPFilterDB).filter(
        IPFilterDB.expires_at <= current_time,
        IPFilterDB.is_active == True
    ).count()
    
    return {
        "total_filters": total_filters,
        "active_filters": active_filters,
        "recently_expired": recently_expired,
        "currently_expired_active": currently_expired_active,
        "retention_period_minutes": EXPIRED_RETENTION_MINUTES,
        "retention_period_days": EXPIRED_RETENTION_MINUTES // (24 * 60)
    }

@app.get("/auth/whoami")
async def whoami(user_info: dict = Depends(verify_api_key)):
    """Get current user information."""
    return {
        "key_name": user_info["key_name"],
        "permissions": user_info["permissions"]
    }

@app.get("/health")
async def health_check():
    """Health check endpoint (no authentication required)."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow(),
        "database": "connected"
    }

@app.get("/config")
async def get_configuration(
    user_info: dict = Depends(require_permission("admin"))
):
    """Get current configuration. Requires 'admin' permission."""
    db = SessionLocal()
    try:
        api_key_count = db.query(APIKeyDB).filter(APIKeyDB.is_active == True).count()
    finally:
        db.close()
    
    return {
        "database_url": DATABASE_URL,
        "output_file_path": OUTPUT_FILE_PATH,
        "min_ipv4_prefix_length": MIN_IPV4_PREFIX_LENGTH,
        "min_ipv6_prefix_length": MIN_IPV6_PREFIX_LENGTH,
        "export_interval_minutes": EXPORT_INTERVAL_MINUTES,
        "auto_export_enabled": AUTO_EXPORT_ENABLED,
        "expired_retention_minutes": EXPIRED_RETENTION_MINUTES,
        "expired_retention_days": EXPIRED_RETENTION_MINUTES // (24 * 60),
        "active_api_keys_count": api_key_count,
        "environment_variables": {
            "EXPORT_INTERVAL_MINUTES": os.getenv("EXPORT_INTERVAL_MINUTES"),
            "AUTO_EXPORT_ENABLED": os.getenv("AUTO_EXPORT_ENABLED"),
            "EXPIRED_RETENTION_MINUTES": os.getenv("EXPIRED_RETENTION_MINUTES")
        }
    }

# Add this function after your configuration constants and before the database setup
def log_configuration():
    """Log configuration constants at startup."""
    print("=" * 50)
    print("IP Filter Management API - Configuration")
    print("=" * 50)
    print(f"DATABASE_URL: {DATABASE_URL}")
    print(f"OUTPUT_FILE_PATH: {OUTPUT_FILE_PATH}")
    print(f"MIN_IPV4_PREFIX_LENGTH: /{MIN_IPV4_PREFIX_LENGTH}")
    print(f"MIN_IPV6_PREFIX_LENGTH: /{MIN_IPV6_PREFIX_LENGTH}")
    print(f"EXPORT_INTERVAL_MINUTES: {EXPORT_INTERVAL_MINUTES}")
    print(f"AUTO_EXPORT_ENABLED: {AUTO_EXPORT_ENABLED}")
    print(f"EXPIRED_RETENTION_MINUTES: {EXPIRED_RETENTION_MINUTES} ({EXPIRED_RETENTION_MINUTES // (24 * 60)} days)")
    print(f"API Keys: Stored in database")
    print(f"Environment variables:")
    print(f"  EXPORT_INTERVAL_MINUTES: {os.getenv('EXPORT_INTERVAL_MINUTES', 'not set (using default)')}")
    print(f"  AUTO_EXPORT_ENABLED: {os.getenv('AUTO_EXPORT_ENABLED', 'not set (using default)')}")
    print(f"  EXPIRED_RETENTION_MINUTES: {os.getenv('EXPIRED_RETENTION_MINUTES', 'not set (using default 1 week)')}")
    print("=" * 50)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)

# random changes 13!
