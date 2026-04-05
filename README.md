# Quantum-Safe AI Agent Gateway

A FastAPI service that issues and verifies **ML-KEM-768 (Kyber)** identities for AI agents.
Built to run for free on Oracle Cloud Always Free (4 ARM cores / 24 GB RAM).

---

## Architecture — 3-Step Handshake

```
AGENT                          GATEWAY (this service)
  │                                     │
  │──── POST /register ───────────────▶│  Gateway generates ML-KEM-768 keypair
  │◀─── { public_key, private_key } ───│  Private key returned ONCE — store it!
  │                                     │
  │──── POST /challenge ──────────────▶│  Gateway encapsulates a shared secret
  │◀─── { challenge_id, ciphertext } ──│  using agent's public key → ciphertext
  │                                     │
  │  Agent decapsulates ciphertext      │
  │  with private key → shared_secret  │
  │                                     │
  │──── POST /verify ─────────────────▶│  Gateway compares shared secrets
  │◀─── { session_token, reputation } ─│  On match: issues token + bumps score
```

---

## Quick Start

### Prerequisites
- Docker + Docker Compose

### Run locally

```bash
git clone <your-repo>
cd pqc_gateway
docker compose up --build
```

API is live at **http://localhost:8000**
Interactive docs at **http://localhost:8000/docs**

---

## Endpoint Reference

### `POST /register`
Register an agent and get its quantum-safe keypair.

```bash
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "swap-agent-001",
    "metadata": { "owner": "alice.sol", "capabilities": ["swap"] }
  }'
```

**Response:**
```json
{
  "agent_id": "swap-agent-001",
  "public_key": "<base64>",
  "private_key_plaintext": "<base64 — store this NOW>",
  "algorithm": "ML-KEM-768"
}
```

---

### `POST /challenge`
Request a PQC ciphertext challenge for an agent.

```bash
curl -X POST http://localhost:8000/challenge \
  -H "Content-Type: application/json" \
  -d '{ "agent_id": "swap-agent-001" }'
```

**Response:**
```json
{
  "challenge_id": "uuid",
  "ciphertext": "<base64 — decapsulate with your private key>",
  "expires_in_seconds": 300
}
```

---

### `POST /verify`
Submit the decapsulated shared secret to complete the handshake.

```bash
curl -X POST http://localhost:8000/verify \
  -H "Content-Type: application/json" \
  -d '{
    "challenge_id": "uuid",
    "shared_secret_b64": "<base64 shared secret>"
  }'
```

**Response:**
```json
{
  "agent_id": "swap-agent-001",
  "verified": true,
  "reputation_score": 1,
  "session_token": "<token>"
}
```

---

## How an Agent Solves the Challenge (Python)

```python
import oqs, base64, requests

# Load your saved private key
private_key_b64 = "<your stored private key>"
private_key = base64.b64decode(private_key_b64)

# 1. Get challenge
resp = requests.post("http://localhost:8000/challenge",
                     json={"agent_id": "swap-agent-001"})
data = resp.json()

# 2. Decapsulate ciphertext → recover shared secret
ciphertext = base64.b64decode(data["ciphertext"])
with oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key) as kem:
    shared_secret = kem.decap_secret(ciphertext)

# 3. Verify
requests.post("http://localhost:8000/verify", json={
    "challenge_id": data["challenge_id"],
    "shared_secret_b64": base64.b64encode(shared_secret).decode(),
})
```

---

## Deploying to Oracle Cloud Always Free

```bash
# On your Oracle ARM instance (Ubuntu 22.04)
sudo apt install docker.io docker-compose -y
git clone <your-repo> && cd pqc_gateway

# Build takes ~5 min (compiles liboqs)
docker compose up -d --build

# Open port 8000 in Oracle's security list
```

---

## Migrating from SQLite → Supabase

In `database.py`, replace `sqlite3.connect(...)` with a `psycopg2` or
`asyncpg` connection using your Supabase connection string:

```
postgresql://postgres:<password>@db.<project>.supabase.co:5432/postgres
```

Then set `DB_PATH` in docker-compose.yml to your Postgres URL.
