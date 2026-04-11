"""
BridgeBase — Quantum-Safe Agent Gateway
Algorithm: ML-KEM-768 (NIST FIPS 203)
Version: 0.3.1 — Public passport pages
"""

import os
import uuid
import base64
import hmac
from datetime import datetime, timezone
from pathlib import Path

import oqs
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel as _BM

from database import Database
from models import (
    RegisterRequest, RegisterResponse,
    ChallengeRequest, ChallengeResponse,
    VerifyRequest, VerifyResponse,
    AgentPassport,
)
from gateway_middleware import issue_token, validate_token
from security import (
    check_rate_limit,
    generate_api_key,
    require_admin,
    TIER_LIMITS,
)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="BridgeBase — Quantum-Safe Agent Gateway",
    description="PQC-hardened identity layer for AI agents. ML-KEM-768 (NIST FIPS 203).",
    version="0.3.1",
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
    admin_key = os.environ.get("BRIDGEBASE_ADMIN_KEY", "not-set")
    print(f"[gateway] Database ready. Algorithm: {ALGORITHM}")
    print(f"[gateway] Admin key configured: {'YES' if admin_key != 'not-set' else 'NO — set BRIDGEBASE_ADMIN_KEY'}")


# ---------------------------------------------------------------------------
# GET / — Dashboard
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse, tags=["meta"], include_in_schema=False)
def dashboard():
    html_path = Path("/app/dashboard.html")
    if html_path.exists():
        html = html_path.read_text()
        html = html.replace("const API = 'http://localhost:8000'", "const API = ''")
        return HTMLResponse(content=html)
    return HTMLResponse(content="<h1>Dashboard not found</h1>", status_code=404)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "algorithm": ALGORITHM, "version": "0.3.1"}


# ---------------------------------------------------------------------------
# GET /agents
# ---------------------------------------------------------------------------

@app.get("/agents", tags=["registry"])
def list_agents():
    agents = db.list_agents()
    return {"agents": agents, "total": len(agents)}


# ---------------------------------------------------------------------------
# POST /register  — rate limited: 5/hour per IP
# ---------------------------------------------------------------------------

@app.post("/register", response_model=RegisterResponse,
          status_code=status.HTTP_201_CREATED, tags=["identity"])
def register(req: RegisterRequest, request: Request) -> RegisterResponse:
    check_rate_limit(request)

    with oqs.KeyEncapsulation(ALGORITHM) as kem:
        public_key_bytes = kem.generate_keypair()
        private_key_bytes = kem.export_secret_key()

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
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return RegisterResponse(
        agent_id=req.agent_id,
        public_key=pub_b64,
        private_key_plaintext=priv_b64,
        algorithm=ALGORITHM,
        message="Registration successful. Store your private key securely.",
    )


# ---------------------------------------------------------------------------
# POST /challenge  — rate limited: 30/min per IP
# ---------------------------------------------------------------------------

@app.post("/challenge", response_model=ChallengeResponse, tags=["identity"])
def challenge(req: ChallengeRequest, request: Request) -> ChallengeResponse:
    check_rate_limit(request)

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
# POST /verify  — rate limited: 30/min per IP
# ---------------------------------------------------------------------------

@app.post("/verify", response_model=VerifyResponse, tags=["identity"])
def verify(req: VerifyRequest, request: Request) -> VerifyResponse:
    check_rate_limit(request)

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
    session_token = issue_token(agent_id=record["agent_id"], reputation=new_score)

    return VerifyResponse(
        agent_id=record["agent_id"],
        verified=True,
        reputation_score=new_score,
        session_token=session_token,
        message="PQC handshake complete. Transaction gating active.",
    )


# ---------------------------------------------------------------------------
# GET /passport/{agent_id}  — JSON API
# ---------------------------------------------------------------------------

@app.get("/passport/{agent_id}", response_model=AgentPassport, tags=["registry"])
def get_passport(agent_id: str) -> AgentPassport:
    passport = db.get_passport(agent_id)
    if passport is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
    return passport


# ---------------------------------------------------------------------------
# GET /passport/{agent_id}/view  — Human-readable public passport page
# ---------------------------------------------------------------------------

@app.get("/passport/{agent_id}/view", response_class=HTMLResponse,
         tags=["registry"], include_in_schema=False)
def view_passport(agent_id: str):
    passport = db.get_passport(agent_id)
    if passport is None:
        return HTMLResponse(content=f"""
        <!DOCTYPE html><html><head><title>Agent Not Found</title>
        <style>body{{background:#030a06;color:#c0e8c0;font-family:'Courier New',monospace;
        display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
        .box{{text-align:center}}.err{{color:#ff4444;font-size:20px;margin-bottom:8px}}
        .sub{{color:#5a8a6a;font-size:13px}}</style></head>
        <body><div class="box"><div class="err">Agent Not Found</div>
        <div class="sub">No agent registered with ID: {agent_id}</div></div></body></html>
        """, status_code=404)

    pub_key = passport.public_key
    pub_key_short = pub_key[:32] + "..." + pub_key[-16:]
    registered = passport.registered_at[:10] if passport.registered_at else "Unknown"
    rep = passport.reputation_score
    metadata = passport.metadata or {}

    # Reputation tier label
    if rep >= 100:
        tier = "ELITE"
        tier_color = "#00ff88"
    elif rep >= 50:
        tier = "TRUSTED"
        tier_color = "#00cc66"
    elif rep >= 10:
        tier = "ACTIVE"
        tier_color = "#0099aa"
    elif rep >= 1:
        tier = "VERIFIED"
        tier_color = "#888888"
    else:
        tier = "NEW"
        tier_color = "#555555"

    meta_rows = ""
    for k, v in metadata.items():
        meta_rows += f'<tr><td class="label">{k}</td><td class="val">{v}</td></tr>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>BridgeBase Passport — {agent_id}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#030a06;color:#c0e8c0;font-family:'Courier New',monospace;
  min-height:100vh;padding:40px 20px}}
.wrap{{max-width:680px;margin:0 auto}}
.header{{margin-bottom:32px}}
.brand{{font-size:11px;letter-spacing:3px;color:#5a8a6a;text-transform:uppercase;margin-bottom:6px}}
.brand a{{color:#5a8a6a;text-decoration:none}}
.brand a:hover{{color:#00ff88}}
.title{{font-size:22px;font-weight:700;color:#fff;margin-bottom:4px}}
.title span{{color:#00ff88}}
.subtitle{{font-size:12px;color:#5a8a6a;letter-spacing:1px}}
.card{{background:#060f08;border:1px solid #0a3a1a;border-radius:8px;
  padding:24px;margin-bottom:16px}}
.card-label{{font-size:9px;letter-spacing:3px;color:#5a8a6a;
  text-transform:uppercase;margin-bottom:16px}}
.agent-id{{font-size:24px;font-weight:700;color:#00ff88;
  word-break:break-all;margin-bottom:4px}}
.tier-badge{{display:inline-block;padding:4px 14px;border-radius:4px;
  font-size:10px;font-weight:700;letter-spacing:2px;margin-bottom:20px;
  background:#001a0a;border:1px solid {tier_color};color:{tier_color}}}
.stats{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:0}}
.stat{{background:#030a06;border:1px solid #0a3a1a;border-radius:6px;padding:14px;text-align:center}}
.stat-num{{font-size:22px;font-weight:700;color:#fff;margin-bottom:2px}}
.stat-lbl{{font-size:9px;letter-spacing:2px;color:#5a8a6a;text-transform:uppercase}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
td{{padding:8px 0;border-bottom:1px solid #0a1a0c;vertical-align:top}}
tr:last-child td{{border-bottom:none}}
td.label{{color:#5a8a6a;width:40%;font-size:10px;letter-spacing:1px;text-transform:uppercase}}
td.val{{color:#c0e8c0;word-break:break-all}}
.pubkey{{font-size:10px;color:#3a6a4a;word-break:break-all;
  background:#020804;border:1px solid #0a1a0c;border-radius:4px;
  padding:10px;line-height:1.6;margin-top:8px}}
.algo-badge{{display:inline-block;background:#002211;border:1px solid #006633;
  color:#00cc66;padding:3px 10px;border-radius:4px;font-size:10px;
  letter-spacing:1px;margin-top:4px}}
.verify-block{{background:#001a0a;border:1px solid #00ff8833;border-radius:6px;
  padding:16px;margin-top:0}}
.verify-title{{font-size:10px;letter-spacing:2px;color:#00ff88;
  text-transform:uppercase;margin-bottom:8px}}
.verify-line{{font-size:11px;color:#5a8a6a;line-height:2;display:flex;
  align-items:center;gap:8px}}
.check{{color:#00ff88;font-size:12px}}
.footer{{margin-top:32px;text-align:center;font-size:10px;color:#5a8a6a;line-height:2}}
.footer a{{color:#3a8a5a;text-decoration:none}}
.footer a:hover{{color:#00ff88}}
.share-btn{{display:inline-block;margin-top:16px;padding:8px 20px;
  border:1px solid #00cc66;color:#00cc66;border-radius:5px;
  font-family:'Courier New',monospace;font-size:10px;letter-spacing:1px;
  cursor:pointer;background:transparent;text-transform:uppercase}}
.share-btn:hover{{background:#001a0a}}
</style>
</head>
<body>
<div class="wrap">

  <div class="header">
    <div class="brand">
      <a href="https://pqc-gateway-production.up.railway.app">BridgeBase Gateway</a>
      &nbsp;/&nbsp; Agent Passport
    </div>
    <div class="title">Bridge<span>Base</span> Verified Agent</div>
    <div class="subtitle">ML-KEM-768 · NIST FIPS 203 · Quantum-Safe Identity</div>
  </div>

  <div class="card">
    <div class="card-label">Agent Identity</div>
    <div class="agent-id">{agent_id}</div>
    <div class="tier-badge">{tier}</div>
    <div class="stats">
      <div class="stat">
        <div class="stat-num">{rep}</div>
        <div class="stat-lbl">Handshakes</div>
      </div>
      <div class="stat">
        <div class="stat-num">{registered}</div>
        <div class="stat-lbl">Registered</div>
      </div>
      <div class="stat">
        <div class="stat-num" style="color:#00ff88">LIVE</div>
        <div class="stat-lbl">Status</div>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-label">Cryptographic Identity</div>
    <table>
      <tr>
        <td class="label">Algorithm</td>
        <td class="val"><span class="algo-badge">ML-KEM-768</span></td>
      </tr>
      <tr>
        <td class="label">Standard</td>
        <td class="val">NIST FIPS 203</td>
      </tr>
      <tr>
        <td class="label">Public Key</td>
        <td class="val"><div class="pubkey">{pub_key_short}</div></td>
      </tr>
      {'<tr><td class="label">Metadata</td><td class="val"><table>' + meta_rows + '</table></td></tr>' if meta_rows else ''}
    </table>
  </div>

  <div class="card">
    <div class="card-label">Verification Status</div>
    <div class="verify-block">
      <div class="verify-title">What this passport proves</div>
      <div class="verify-line"><span class="check">+</span> Agent registered with ML-KEM-768 post-quantum keypair</div>
      <div class="verify-line"><span class="check">+</span> Identity verified by BridgeBase Gateway</div>
      <div class="verify-line"><span class="check">+</span> Every transaction requires a live PQC handshake</div>
      <div class="verify-line"><span class="check">+</span> Reputation score is on-chain verifiable</div>
      <div class="verify-line"><span class="check">+</span> Harvest-now-decrypt-later attack resistant</div>
    </div>
  </div>

  <div style="text-align:center">
    <button class="share-btn" onclick="navigator.clipboard.writeText(window.location.href).then(()=>this.textContent='Copied!')">
      Copy Passport URL
    </button>
  </div>

  <div class="footer">
    Powered by <a href="https://pqc-gateway-production.up.railway.app">BridgeBase</a>
    &nbsp;·&nbsp;
    <a href="https://twitter.com/BridgeBaseAI">@BridgeBaseAI</a>
    &nbsp;·&nbsp;
    <a href="https://github.com/BridgeBaseAI/pqc-gateway">GitHub</a>
    &nbsp;·&nbsp;
    <a href="https://www.npmjs.com/package/bridgebase-sdk">npm</a>
    <br>
    The Trust Layer for the Agentic Economy
  </div>

</div>
</body>
</html>"""

    return HTMLResponse(content=html)


# ---------------------------------------------------------------------------
# POST /validate-token  — rate limited: 60/min per IP
# ---------------------------------------------------------------------------

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
def validate_session_token(req: ValidateTokenRequest, request: Request):
    check_rate_limit(request)

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
# POST /dev/solve  — rate limited: 30/min per IP
# ---------------------------------------------------------------------------

class SolveRequest(_BM):
    private_key_b64: str
    ciphertext_b64: str

class SolveResponse(_BM):
    shared_secret_b64: str

@app.post("/dev/solve", response_model=SolveResponse, tags=["dev"])
def dev_solve(req: SolveRequest, request: Request) -> SolveResponse:
    check_rate_limit(request)

    private_key = base64.b64decode(req.private_key_b64)
    ciphertext = base64.b64decode(req.ciphertext_b64)
    with oqs.KeyEncapsulation(ALGORITHM, secret_key=private_key) as kem:
        shared_secret = kem.decap_secret(ciphertext)
    return SolveResponse(shared_secret_b64=base64.b64encode(shared_secret).decode())


# ---------------------------------------------------------------------------
# POST /admin/create-key  — admin only
# ---------------------------------------------------------------------------

class CreateKeyRequest(_BM):
    tier: str = "free"
    label: str = ""

@app.post("/admin/create-key", tags=["admin"])
def create_api_key(req: CreateKeyRequest, request: Request):
    require_admin(request)
    if req.tier not in TIER_LIMITS:
        raise HTTPException(status_code=400,
            detail=f"Invalid tier. Choose: {list(TIER_LIMITS.keys())}")
    return generate_api_key(tier=req.tier, label=req.label)


# ---------------------------------------------------------------------------
# GET /admin/stats  — admin only
# ---------------------------------------------------------------------------

@app.get("/admin/stats", tags=["admin"])
def admin_stats(request: Request):
    require_admin(request)
    agents = db.list_agents()
    return {
        "total_agents": len(agents),
        "algorithm": ALGORITHM,
        "version": "0.3.1",
        "agents": agents,
    }
