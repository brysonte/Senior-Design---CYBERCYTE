import uvicorn
import os
import secrets
import passlib.hash
from fastapi import FastAPI, Request, Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv
from datetime import datetime
from passlib.hash import argon2

# --- SQLAlchemy Imports ---
from sqlalchemy import create_engine, Column, BIGINT, String, Index, text, func, or_, desc, Boolean, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel

# --- Pydantic Settings for Configuration ---
from pydantic_settings import BaseSettings

load_dotenv()
# 1. Configuration
# Pydantic will automatically read this from an environment variable!
# e.g., export DATABASE_URL="postgresql+psycopg2://zeek_writer:your_password@localhost/zeek_logs"
class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+psycopg2://zeek_writer:your_secure_password@localhost/zeek_logs"
    # A single "root" key for using the dashboard.
    # Set this in your environment: API KEY 
    API_KEY = os.getenv("ADMIN_API_KEY")

settings = Settings()

# --- API Key Security Scheme ---
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# 2. SQLAlchemy Database Setup
engine = create_engine(settings.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# 3. SQLAlchemy ORM Model
# This class defines the tables in Python
class Client(Base):
    """
    New table to store registered clients (Zeek/Osquery hosts).
    """
    __tablename__ = "clients"
    
    id = Column(BIGINT, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    # We store the *hash* of the API key, not the key itself
    hashed_api_key = Column(String(255), unique=True, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    
    # Relationship: A client has many logs
    logs = relationship("ZeekLog", back_populates="client")

class ZeekLog(Base):
    __tablename__ = "zeek_logs"

    id = Column(BIGINT, primary_key=True)
    event_ts = Column(TIMESTAMP(timezone=True), nullable=False)
    log_source = Column(String(50), index=True)
    raw_log = Column(JSONB, nullable=False)

# --- NEW FOREIGN KEY (column was added manually in Step 2) ---
    client_id = Column(BIGINT, ForeignKey("clients.id"), nullable=True, index=True)
    
    # Relationship: A log belongs to one client
    client = relationship("Client", back_populates="logs")

    # This ensures the GIN index is created with the model
    __table_args__ = (
        Index('idx_zeek_logs_raw_log_gin', 'raw_log', postgresql_using='gin'),
    )

# Create the table in the database (if it doesn't exist)
Base.metadata.create_all(bind=engine)

# --- Pydantic Models (for request bodies) ---
# ==============================================================================
class ClientRegister(BaseModel):
    name: str

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Dependency: Check Ingest API Key ---
async def get_client_from_key(api_key: str = Security(api_key_header), db: Session = Depends(get_db)):
    """
    Finds an active client by their plain-text API key.
    This is the core security for log ingestion.
    """
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header"
        )
        
    # Securely check the key against all stored hashes.
    # This is the standard, secure method.
    clients = db.query(Client).filter(Client.is_active == True).all()
    for client in clients:
        if argon2.verify(api_key, client.hashed_api_key):
            return client # Success!
            
    # If no key matches
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or inactive API key"
    )

# --- Dependency: Check Admin API Key ---
async def check_admin_key(api_key: str = Security(api_key_header)):
    """
    Checks for the root admin key to protect dashboard/admin endpoints.
    """
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header"
        )
    if not secrets.compare_digest(api_key, settings.ADMIN_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Admin API Key"
        )

@app.post("/logs/ingest")
async def receive__logs(request: Request, db: Session = Depends(get_db)):
    """
    This endpoint receives log batches from Filebeat.
    """
    # Filebeat sends a list of JSON objects
    try:
        log_batch = await request.json()

    # log_batch is now a Python list of dictionaries
    # You can now process them (e.g., print them, save to a DB, etc.)

        print(f"--- Received batch of {len(log_batch)} log(s) ---")

    # Example: Print the 'uid' from the first 5 conn logs in the batch
        logs_to_insert = []
        for log in log_batch:
            # --- Parse the log ---
            log_type = log.get("log_type")
            event_ts = None
            log_source = None
            # --- ROUTER LOGIC ---
            
            if log_type == "zeek":
                # --- ZEEK PARSING (your existing logic) ---
                ts_string = log.get('@timestamp')
                event_ts = datetime.fromisoformat(ts_string.replace('Z', '+00:00')) if ts_string else None
                log_path = log.get('log', {}).get('file', {}).get('path', 'unknown.log')
                log_source = os.path.basename(log_path).split('.')[0]
            
            elif log_type == "osquery":
                # --- OSQUERY PARSING (NEW LOGIC) ---
                unix_time = log.get('unixTime')
                event_ts = datetime.fromtimestamp(int(unix_time)) if unix_time else None
                log_source = log.get('name', 'osquery_unknown')
            
            if log_source:
                logs_to_insert.append({
                    "event_ts": event_ts,
                    "log_source": log_source,
                    "raw_log": log,
                    "client_id": client.id  # --- Link log to the authenticated client
                })

        # --- Perform a high-efficiency bulk insert (No Change) ---
        if logs_to_insert:
            print(f"--- Inserting batch of {len(logs_to_insert)} log(s) ---")
            db.bulk_insert_mappings(ZeekLog, logs_to_insert)
            db.commit()
        
        return {"status": "ok", "received": len(log_batch), "client_name": client.name}
    
    except Exception as e:
        print(f"Error processing batch: {e}")
        # Rollback in case of error
        db.rollback()
        return {"status": "error", "error": str(e)}

admin_deps = [Depends(check_admin_key)]

# --- Client Management Endpoints ---

@app.post("/api/clients", dependencies=admin_deps)
async def register_client(client_data: ClientRegister, db: Session = Depends(get_db)):
    """
    Registers a new client and returns its API key.
    This is called by the Streamlit dashboard.
    """
    name = client_data.name
    # Check if name already exists
    existing = db.query(Client).filter(Client.name == name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Client with this name already exists")
        
    # 1. Generate a new plain-text API key
    api_key = secrets.token_hex(32)
    
    # 2. Hash the key for storage
    hashed_api_key = argon2.hash(api_key)
    
    # 3. Create new client record
    new_client = Client(name=name, hashed_api_key=hashed_api_key)
    db.add(new_client)
    db.commit()
    db.refresh(new_client)
    
    # 4. Return the plain-text key (THIS IS THE ONLY TIME IT'S SHOWN)
    return {"id": new_client.id, "name": new_client.name, "api_key": api_key}


@app.get("/api/clients/status", dependencies=admin_deps)
async def get_client_statuses(db: Session = Depends(get_db)):
    """
    Gets all clients and their "last seen" timestamp.
    """
    # This query joins clients with logs, gets the max timestamp,
    # and labels it 'last_seen'.
    query = text("""
    SELECT 
        c.id, 
        c.name, 
        c.hashed_api_key, 
        c.is_active, 
        c.created_at,
        MAX(zl.event_ts) as last_seen
    FROM clients c
    LEFT JOIN zeek_logs zl ON c.id = zl.client_id
    GROUP BY c.id
    ORDER BY c.name
    """)
    
    results = db.execute(query).fetchall()
    
    # We need to replace the hashed key with "..." for security
    clients_status = []
    for r in results:
        clients_status.append({
            "id": r.id,
            "name": r.name,
            "api_key_hash": r.hashed_api_key[:10] + "..." if r.hashed_api_key else "N/A",
            "is_active": r.is_active,
            "created_at": r.created_at,
            "last_seen": r.last_seen
        })
    return clients_status


@app.put("/api/clients/{client_id}/toggle", dependencies=admin_deps)
async def toggle_client_status(client_id: int, db: Session = Depends(get_db)):
    """
    Activates or deactivates a client.
    """
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
        
    client.is_active = not client.is_active
    db.commit()
    db.refresh(client)
    return {"id": client.id, "name": client.name, "is_active": client.is_active}


# --- Dashboard Stats Endpoints (Now secured) ---

@app.get("/api/stats", dependencies=admin_deps)
async def get_global_stats(db: Session = Depends(get_db)):
    total_logs = db.query(func.count(ZeekLog.id)).scalar()
    unique_sources = db.query(func.count(func.distinct(ZeekLog.log_source))).scalar()
    unique_clients = db.query(func.count(Client.id)).scalar() # Total registered clients
    return {
        "total_logs": total_logs,
        "unique_sources": unique_sources,
        "unique_clients": unique_clients
    }


@app.get("/api/logs/over_time", dependencies=admin_deps)
async def get_logs_over_time(db: Session = Depends(get_db)):
    query = text("""
    SELECT date_trunc('hour', event_ts) as hour, log_source, COUNT(*) as count
    FROM zeek_logs
    WHERE event_ts > NOW() - INTERVAL '1 day'
    GROUP BY hour, log_source ORDER BY hour
    """)
    results = db.execute(query).fetchall()
    return [
        {"hour": r.hour, "log_source": r.log_source, "count": r.count}
        for r in results
    ]


@app.get("/api/clients", dependencies=admin_deps)
async def get_all_clients(db: Session = Depends(get_db)):
    clients = db.query(Client).order_by(Client.name).all()
    return [{"id": c.id, "name": c.name} for c in clients]


@app.get("/api/client/{client_id}", dependencies=admin_deps)
async def get_client_details(client_id: int, db: Session = Depends(get_db)):
    # Now we can filter by the new client_id FK (which is much faster)
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
        
    total_logs = db.query(func.count(ZeekLog.id)).filter(ZeekLog.client_id == client_id).scalar()
    unique_sources = db.query(func.count(func.distinct(ZeekLog.log_source))).filter(ZeekLog.client_id == client_id).scalar()
    
    logs_query = db.query(
        ZeekLog.event_ts, ZeekLog.log_source, ZeekLog.raw_log
    ).filter(ZeekLog.client_id == client_id).order_by(desc(ZeekLog.event_ts)).limit(100).all()

    return {
        "client_name": client.name,
        "stats": {"total_logs": total_logs, "unique_sources": unique_sources},
        "logs": [
            {"event_ts": r.event_ts, "log_source": r.log_source, "raw_log": r.raw_log}
            for r in logs_query
        ]
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
