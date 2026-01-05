"""
Vetra AI + Syra AI - Enterprise-Grade Secure Custom AI
"""

import os, time, secrets, re, bcrypt, json
from datetime import datetime
from typing import Dict, List, Any
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import asyncpg, aioredis, uvicorn, jwt
from cryptography.fernet import Fernet
from slowapi import Limiter
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

# ===========================
# CONFIG
# ===========================
DATABASE_URL = os.getenv("DATABASE_URL")
REDIS_URL = os.getenv("REDIS_URL")
APP_SECRET = os.getenv("APP_SECRET") or secrets.token_urlsafe(32)
ADMIN_JWT_SECRET = os.getenv("ADMIN_JWT_SECRET") or secrets.token_urlsafe(32)
DEFAULT_RATE = "60/minute"
API_KEY_MAX_USES = 1000
API_KEY_EXPIRE_DAYS = 30
FERNET_KEY = os.getenv("FERNET_KEY") or Fernet.generate_key().decode()
fernet = Fernet(FERNET_KEY.encode())

if not DATABASE_URL or not REDIS_URL:
    raise RuntimeError("❌ Missing DATABASE_URL or REDIS_URL")

# ===========================
# METRICS
# ===========================
REQ = Counter("vetra_requests", "Total requests", ["endpoint"])
LAT = Histogram("vetra_latency", "Latency", ["endpoint"])

# ===========================
# APP INIT
# ===========================
app = FastAPI(title="Vetra AI + Syra AI", version="1.0")
app.add_middleware(SessionMiddleware, secret_key=APP_SECRET)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST","GET"],
    allow_headers=["*"]
)
limiter = Limiter(key_func=get_remote_address, default_limits=[DEFAULT_RATE])
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

# ===========================
# STARTUP
# ===========================
@app.on_event("startup")
async def startup():
    ssl_opt = True
    if "localhost" in DATABASE_URL or "127.0.0.1" in DATABASE_URL:
        ssl_opt = False
    app.state.db = await asyncpg.create_pool(DATABASE_URL, ssl=ssl_opt)
    app.state.redis = await aioredis.from_url(REDIS_URL)
    async with app.state.db.acquire() as c:
        await c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE,
            name TEXT,
            created_at BIGINT
        );
        """)
        await c.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id SERIAL PRIMARY KEY,
            email TEXT,
            key_hash TEXT,
            uses INT DEFAULT 0,
            max_uses INT DEFAULT 1000,
            revoked BOOLEAN DEFAULT FALSE,
            expires_at BIGINT,
            created BIGINT,
            bound_ip TEXT
        );
        """)
        await c.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id SERIAL PRIMARY KEY,
            api_key_id INT,
            email TEXT,
            endpoint TEXT,
            meta BYTEA,
            ts BIGINT
        );
        """)

@app.on_event("shutdown")
async def shutdown():
    await app.state.db.close()
    await app.state.redis.close()

# ===========================
# MODELS
# ===========================
class RegisterModel(BaseModel):
    email: str
    name: str = None

class AskModel(BaseModel):
    prompt: str

# ===========================
# HELPERS
# ===========================
def generate_api_key() -> str:
    return "vetra_" + secrets.token_urlsafe(28)

def hash_key(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

def verify_key(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def encrypt_data(data: dict) -> bytes:
    return fernet.encrypt(json.dumps(data).encode())

def decrypt_data(data: bytes) -> dict:
    return json.loads(fernet.decrypt(data).decode())

def admin_create_token(name: str) -> str:
    payload = {"sub": name, "iat": int(time.time()), "exp": int(time.time()) + 3600}
    return jwt.encode(payload, ADMIN_JWT_SECRET, algorithm="HS256")

def admin_verify_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, ADMIN_JWT_SECRET, algorithms=["HS256"])
    except:
        raise HTTPException(401, "Invalid admin token")

BLOCK_PATTERNS = [r"(ignore|bypass).*(rules|system)", r"(hack|crack|steal|ddos)", r"(admin|root|password)"]
def check_prompt(prompt: str):
    if len(prompt) > 4000:
        raise HTTPException(400, "Prompt too long")
    for p in BLOCK_PATTERNS:
        if re.search(p, prompt.lower()):
            raise HTTPException(400, "Prompt blocked by policy")

async def record_audit(api_key_id: int, email: str, endpoint: str, meta: dict = None):
    meta = meta or {}
    encrypted_meta = encrypt_data(meta)
    async with app.state.db.acquire() as c:
        await c.execute("INSERT INTO audit_logs (api_key_id,email,endpoint,meta,ts) VALUES ($1,$2,$3,$4,$5)",
                        api_key_id, email, endpoint, encrypted_meta, int(time.time()))

# ===========================
# CUSTOM AI BRAINS
# ===========================
# Original Vetra AI brain
class VetraBrain:
    def respond(self, user: str, prompt: str):
        return {"answer": f"Vetra AI processed: {prompt[:200]}", "reason": "Original Vetra logic"}

vetra_brain = VetraBrain()

# Syra AI - custom learning model
class SyraAI:
    def __init__(self):
        self.short_memory: Dict[str, List[str]] = {}
        self.long_memory: Dict[str, List[str]] = {}

    def respond(self, user: str, prompt: str):
        self.short_memory.setdefault(user, []).append(prompt)
        self.short_memory[user] = self.short_memory[user][-10:]
        self.long_memory.setdefault(user, []).append(prompt)
        return {"answer": f"Syra AI processed: {prompt[::-1]}", "reason": f"Prompt length {len(prompt)}"}

syra_brain = SyraAI()

# ===========================
# ROUTES
# ===========================
@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/register")
@limiter.limit("5/minute")
async def register(payload: RegisterModel, request: Request):
    now = int(time.time())
    async with app.state.db.acquire() as c:
        await c.execute("INSERT INTO users (email,name,created_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
                        payload.email.lower(), payload.name or "", now)
    request.session["user_email"] = payload.email.lower()
    return {"message": "Registered successfully. Use /create_key to get API key."}

@app.post("/create_key")
@limiter.limit("3/minute")
async def create_key(request: Request):
    email = request.session.get("user_email")
    if not email:
        raise HTTPException(401, "Not logged in")
    key_plain = generate_api_key()
    key_hash = hash_key(key_plain)
    now = int(time.time())
    expires = now + API_KEY_EXPIRE_DAYS*24*60*60
    client_ip = request.client.host if request.client else None
    async with app.state.db.acquire() as c:
        await c.execute("INSERT INTO api_keys (email,key_hash,created,expires_at,bound_ip,max_uses) VALUES ($1,$2,$3,$4,$5,$6)",
                        email, key_hash, now, expires, client_ip, API_KEY_MAX_USES)
    return {"api_key": key_plain, "note": "Save now, will not be shown again."}

@app.post("/ask")
@limiter.limit("60/minute")
async def ask(request: Request, data: AskModel):
    check_prompt(data.prompt)
    key = request.headers.get("Authorization")
    if not key:
        raise HTTPException(401, "Missing API key")

    async with app.state.db.acquire() as c:
        rows = await c.fetch("SELECT * FROM api_keys WHERE revoked=false") or []
        valid = False
        email = None
        api_key_id = None
        for r in rows:
            if r.get("key_hash") and verify_key(key, r["key_hash"]):
                valid = True
                email = r["email"]
                api_key_id = r["id"]
                if r["expires_at"] < int(time.time()):
                    raise HTTPException(403, "API key expired")
                if r["uses"] >= r["max_uses"]:
                    raise HTTPException(403, "Usage limit reached")
                break

    if not valid:
        raise HTTPException(403, "Invalid API key")

    async with app.state.db.acquire() as c:
        await c.execute("UPDATE api_keys SET uses=uses+1 WHERE id=$1", api_key_id)

    await record_audit(api_key_id, email, "/ask", {"prompt_len": len(data.prompt)})

    # Combined response: Vetra + Syra
    vetra_resp = vetra_brain.respond(email, data.prompt)
    syra_resp = syra_brain.respond(email, data.prompt)

    return {
        "vetra": vetra_resp,
        "syra": syra_resp,
        "user": email,
        "time": datetime.utcnow().isoformat()
    }

# ===========================
# RUN
# ===========================
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT","8000")), reload=True)
