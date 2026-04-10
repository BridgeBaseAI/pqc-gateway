"""
Quantum-Safe AI Agent Gateway
FastAPI service exposing PQC-based agent registration and challenge endpoints.
Algorithm: ML-KEM-768 (NIST FIPS 203)
"""

import os
import uuid
import base64
import json
import hmac
from datetime import datetime, timezone
from pathlib import Path

import oqs
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from database import Database
from models import (
    RegisterRequest,
    RegisterResponse,
    ChallengeRequest,
    ChallengeResponse,
    VerifyRequest,
    VerifyResponse,
    AgentPassport,
)
from gateway_middleware import issue_token, validate_token  # Layer 4

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="BridgeBase — Quantum-Safe Agent Gateway",
    description="PQC-hardened identity layer for AI agents. Uses ML-KEM-768 (Kyber) for key encapsulation.",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

db = Database(os.getenv("DB_PATH", "/app/data/registry.db"))
ALGORITHM = "ML-KEM-768"
CHALLENGE_TTL_SECONDS = int(os.getenv("CHALLENGE_TTL_SECONDS", "300"))


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

@app.on_event("startup")
def on_startup() -> None:
    db.init()
    print(f"[gateway] Database ready. Algorithm: {ALGORITHM}")


# ---------------------------------------------------------------------------
# GET / — Serve the dashboard
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse, tags=["meta"], include_in_schema=False)
def dashboard():
    html_path = Path("/app/dashboard.html")
    if html_path.exists():
        html = html_path.read_text()
        html = html.replace(
            "const API = 'http://localhost:8000'",
            "const API = ''"
        )
        return HTMLResponse(content=html)
    return HTMLResponse(content="<h1>Dashboard not found</h1>", status_code=404)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "algorithm": ALGORITHM, "layer": 4}


# ---------------------------------------------------------------------------
# GET /agents
# ---------------------------------------------------------------------------

@app.get("/agents", tags=["registry"])
def list_agents():
    agents = db.list_agents()
    return {"agents": agents, "total": len(agents)}


# ---------------------------------------------------------------------------
# POST /register
# ---------------------------------------------------------------------------

@app.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["identity"],
)
def register(req: RegisterRequest) -> RegisterResponse:
    with oqs.KeyEncapsulation(ALGORITHM) as kem:
        public_key_bytes: bytes = kem.generate_keypair()
        private_key_bytes: bytes = kem.export_secret_key()

    pub_b64 = base64.b64encode(public_key_bytes).decode()
    priv_b64 = base64.b64encode(private_key_bytes).decode()

    passport = AgentPassport(
        agent_id=req.agent_id,
        public_key=pub_b64,
        metadata=req.metadata,
        registered_at=datetime.now(timezone.utc).isoformat(),
        reputation_score=0,
    )

    try:
        db.save_passport(passport)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    return RegisterResponse(
        agent_id=req.agent_id,
        public_key=pub_b64,
        private_key_plaintext=priv_b64,
        algorithm=ALGORITHM,
        message="Registration successful. Store your private key securely.",
    )


# ---------------------------------------------------------------------------
# POST /challenge
# ---------------------------------------------------------------------------

@app.post("/challenge", response_model=ChallengeResponse, tags=["identity"])
def challenge(req: ChallengeRequest) -> ChallengeResponse:
    passport = db.get_passport(req.agent_id)
    if passport is None:
        raise HTTPException(status_code=404, detail=f"Agent '{req.agent_id}' not registered.")

    public_key_bytes = base64.b64decode(passport.public_key)

    with oqs.KeyEncapsulation(ALGORITHM) as kem:
        ciphertext_bytes, shared_secret_bytes = kem.encap_secret(public_key_bytes)

    challenge_id = str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc).timestamp() + CHALLENGE_TTL_SECONDS

    db.save_challenge(
        challenge_id=challenge_id,
        agent_id=req.agent_id,
        shared_secret_b64=base64.b64encode(shared_secret_bytes).decode(),
        expires_at=expires_at,
    )

    return ChallengeResponse(
        challenge_id=challenge_id,
        ciphertext=base64.b64encode(ciphertext_bytes).decode(),
        algorithm=ALGORITHM,
        expires_in_seconds=CHALLENGE_TTL_SECONDS,
        instructions="Decapsulate with your ML-KEM-768 private key. POST recovered secret to /verify.",
    )


# ---------------------------------------------------------------------------
# POST /verify  ← UPDATED: now stores session token properly
# ---------------------------------------------------------------------------

@app.post("/verify", response_model=VerifyResponse, tags=["identity"])
def verify(req: VerifyRequest) -> VerifyResponse:
    record = db.get_challenge(req.challenge_id)

    if record is None:
        raise HTTPException(status_code=404, detail="Challenge not found.")
    if record["used"]:
        raise HTTPException(status_code=410, detail="Challenge already consumed.")

    now = datetime.now(timezone.utc).timestamp()
    if now > record["expires_at"]:
        raise HTTPException(status_code=408, detail="Challenge expired.")

    if not hmac.compare_digest(record["shared_secret_b64"], req.shared_secret_b64):
        raise HTTPException(status_code=401, detail="Shared secret mismatch — handshake failed.")

    db.mark_challenge_used(req.challenge_id)
    new_score = db.increment_reputation(record["agent_id"])

    # Issue token via middleware (Layer 4)
    session_token = issue_token(agent_id=record["agent_id"], reputation=new_score)

    return VerifyResponse(
        agent_id=record["agent_id"],
        verified=True,
        reputation_score=new_score,
        session_token=session_token,
        message="PQC handshake complete. Transaction gating active.",
    )


# ---------------------------------------------------------------------------
# GET /passport/{agent_id}
# ---------------------------------------------------------------------------

@app.get("/passport/{agent_id}", response_model=AgentPassport, tags=["registry"])
def get_passport(agent_id: str) -> AgentPassport:
    passport = db.get_passport(agent_id)
    if passport is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
    return passport


# ---------------------------------------------------------------------------
# POST /validate-token  ← NEW: Solana transaction gate
# ---------------------------------------------------------------------------

from pydantic import BaseModel as _BM

class ValidateTokenRequest(_BM):
    agent_id: str
    session_token: str

class ValidateTokenResponse(_BM):
    cleared: bool
    agent_id: str
    reputation: int
    tx_count: int
    message: str

@app.post("/validate-token", response_model=ValidateTokenResponse, tags=["layer4"])
def validate_session_token(req: ValidateTokenRequest):
    """
    Transaction gate — agents must call this before any Solana transaction.
    Returns 200 if cleared, 403 if blocked.
    """
    try:
        result = validate_token(agent_id=req.agent_id, token=req.session_token)
        return ValidateTokenResponse(
            cleared=True,
            agent_id=result["agent_id"],
            reputation=result["reputation"],
            tx_count=result["tx_count"],
            message="Transaction authorized by BridgeBase gateway",
        )
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))


# ---------------------------------------------------------------------------
# POST /dev/solve — browser helper
# ---------------------------------------------------------------------------

class SolveRequest(_BM):
    private_key_b64: str
    ciphertext_b64: str

class SolveResponse(_BM):
    shared_secret_b64: str

@app.post("/dev/solve", response_model=SolveResponse, tags=["dev"])
def dev_solve(req: SolveRequest) -> SolveResponse:
    private_key = base64.b64decode(req.private_key_b64)
    ciphertext  = base64.b64decode(req.ciphertext_b64)
    with oqs.KeyEncapsulation(ALGORITHM, secret_key=private_key) as kem:
        shared_secret = kem.decap_secret(ciphertext)
    return SolveResponse(shared_secret_b64=base64.b64encode(shared_secret).decode())
