# BridgeBase — Quantum-Safe AI Agent Gateway

**The Trust Layer for the Agentic Economy**

[![npm version](https://img.shields.io/npm/v/bridgebase-sdk?color=00ff88&labelColor=030a06&style=flat-square)](https://www.npmjs.com/package/bridgebase-sdk)
[![Live Gateway](https://img.shields.io/badge/gateway-online-00ff88?labelColor=030a06&style=flat-square)](https://pqc-gateway-production.up.railway.app)
[![NIST FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203-00cc66?labelColor=030a06&style=flat-square)](https://csrc.nist.gov/pubs/fips/203/final)
[![License: MIT](https://img.shields.io/badge/license-MIT-00ff88?labelColor=030a06&style=flat-square)](LICENSE)

---

BridgeBase is a production-grade gateway that gives AI agents quantum-safe identities using **ML-KEM-768** (NIST FIPS 203). Every agent registers a post-quantum keypair, authenticates via a 3-step cryptographic handshake, and receives a session token before any transaction is allowed through.

No agent acts without proof. No transaction passes without verification.

---

## The Problem

AI agents are executing real transactions — swaps, transfers, contract calls — with no cryptographic proof of identity. Current signing methods (ECDSA, RSA) are vulnerable to harvest-now-decrypt-later attacks. A quantum adversary can collect today's signed messages and decrypt them once quantum computers mature.

The agentic economy needs a trust layer built for the post-quantum era.

---

## What BridgeBase Does

```
AI Agent                    BridgeBase Gateway              Solana / Any Chain
   |                               |                               |
   |-- register(agent_id) -------> |                               |
   |<- ML-KEM-768 keypair -------- |                               |
   |                               |                               |
   |-- challenge(agent_id) ------> |                               |
   |<- ciphertext (encapsulated) - |                               |
   |                               |                               |
   |-- verify(shared_secret) ----> |                               |
   |<- session_token ------------- |                               |
   |                               |                               |
   |-- validate_token() ---------> |                               |
   |                               |-- transaction CLEARED ------> |
```

---

## Architecture

```
bridgebase/
  main.py                  FastAPI gateway, all endpoints
  database.py              SQLite, persistent Railway volume
  gateway_middleware.py    Session token store + validator
  security.py              Rate limiting + API key tiers
  bridgebase_sdk.py        Python SDK
  bridgebase-sdk.js        JavaScript SDK (CJS + ESM)
  layer4_demo.py           Solana transaction gating
  layer7_reputation.py     On-chain reputation (hash-chained)
  dashboard.html           Dark terminal UI, 5 tabs
```

**Stack:** FastAPI · ML-KEM-768 (liboqs) · SQLite · Solana devnet · Railway

---

## Quick Start

### Python

```bash
pip install bridgebase-sdk
```

```python
from bridgebase_sdk import BridgeBaseClient

client = BridgeBaseClient(
    gateway_url="https://pqc-gateway-production.up.railway.app"
)

# Register once — save the private key
result = client.register(agent_id="my-agent", metadata={})
private_key = result["private_key"]  # store this securely

# Authenticate every session
token = client.authenticate(agent_id="my-agent", private_key=private_key)

# Gate any transaction
cleared = client.validate_token(agent_id="my-agent", session_token=token)
```

### JavaScript (ESM)

```bash
npm install bridgebase-sdk
```

```js
import { BridgeBaseClient } from 'bridgebase-sdk'

const client = new BridgeBaseClient()

const result = await client.register('my-agent')
const privateKey = result.privateKey  // store this securely

const token = await client.authenticate('my-agent', privateKey)
const cleared = await client.validateToken('my-agent', token)
```

### JavaScript (CJS)

```js
const { BridgeBaseClient } = require('bridgebase-sdk')
```

---

## API Reference

### Live URL
```
https://pqc-gateway-production.up.railway.app
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Gateway status |
| GET | `/agents` | List all registered agents |
| POST | `/register` | Register agent, generate ML-KEM-768 keypair |
| POST | `/challenge` | Issue PQC challenge (ciphertext) |
| POST | `/verify` | Verify shared secret, issue session token |
| GET | `/passport/{id}` | Agent public passport |
| POST | `/validate-token` | Transaction gate — returns cleared/blocked |
| POST | `/dev/solve` | Browser-side decapsulation helper |
| POST | `/admin/create-key` | Generate API key (admin only) |
| GET | `/admin/stats` | Gateway statistics (admin only) |

### Rate Limits

| Endpoint | Limit |
|----------|-------|
| `/register` | 5/hour per IP |
| `/challenge` | 30/min per IP |
| `/verify` | 30/min per IP |
| `/validate-token` | 60/min per IP |

---

## SDK Methods

### Python SDK

```python
client.health()                          # gateway status
client.register(agent_id, metadata)      # register agent
client.authenticate(agent_id, priv_key) # full 3-step handshake
client.validate_token(agent_id, token)  # gate transaction
client.get_passport(agent_id)           # public passport
client.list_agents()                    # all agent IDs
client.reputation(agent_id)             # reputation score
```

### JavaScript SDK

```js
client.health()
client.register(agentId, metadata)
client.authenticate(agentId, privateKey)
client.validateToken(agentId, token)
client.getPassport(agentId)
client.listAgents()
client.reputation(agentId)
```

---

## API Key Tiers

| Tier | Agents | Auths/month | Price |
|------|--------|-------------|-------|
| Free | 3 | 500 | $0 |
| Premium | Unlimited | Unlimited | $19/lifetime beta access |

Generate keys via the dashboard or `/admin/create-key`.

---

## Use Cases

**Solana AI Agents** — Any agent executing swaps, transfers, or staking must pass a PQC handshake before the transaction is cleared. Unverified agents are blocked at the gateway.

**ElizaOS / Virtuals** — Drop BridgeBase into any ElizaOS or Virtuals agent as a trust middleware layer. The SDK works in Node.js with no extra dependencies.

**Multi-agent pipelines** — In pipelines where agents call other agents, BridgeBase ensures every hop is cryptographically verified, not just the entry point.

**Compliance-first deployments** — NIST FIPS 203 compliance for teams that need to demonstrate post-quantum readiness to auditors or enterprise customers.

---

## On-Chain Reputation

BridgeBase tracks a hash-chained reputation log per agent on Solana devnet. Each successful handshake increments reputation. Each blocked transaction is recorded. The log is tamper-evident — any modification breaks the chain.

```python
score = client.reputation("my-agent")
```

Live demo wallet: `FR17RiSf6nPRDT7P8cWKZ1F6Q5vjh4sUsrfGXjQyuBFK`

---

## Self-Hosting

### Requirements

- Python 3.11+
- Docker (optional)
- liboqs system library

### Run locally

```bash
git clone https://github.com/BridgeBaseAI/pqc-gateway
cd pqc-gateway
pip install -r requirements.txt
uvicorn main:app --reload
```

### Docker

```bash
docker compose up
```

### Environment variables

```
DB_PATH=./data/registry.db
BRIDGEBASE_ADMIN_KEY=your-admin-key
```

---

## Security

- **Algorithm:** ML-KEM-768 (CRYSTALS-Kyber), NIST FIPS 203
- **Library:** liboqs (Open Quantum Safe project)
- **Private keys** are never stored — returned once at registration
- **Session tokens** are time-limited and single-use per validation
- **Rate limiting** on all auth endpoints to prevent brute force
- **Admin endpoints** require a separate admin API key

To report a security issue: bridgebaseai@gmail.com

---

## Project Status

| Layer | Description | Status |
|-------|-------------|--------|
| 1 | PQC Gateway Core — ML-KEM-768 | Complete |
| 2 | Dashboard — dark terminal UI | Complete |
| 3 | Public URL — Railway | Complete |
| 4 | Solana Transaction Gating | Complete |
| 5 | Permanent deployment | Complete |
| 6 | Python + JavaScript SDK | Complete |
| 7 | On-chain reputation | Complete |
| 8 | Security — rate limiting + API keys | Complete |
| 9 | npm package — bridgebase-sdk | Complete |

---

## Links

- Live gateway: https://pqc-gateway-production.up.railway.app
- npm: https://www.npmjs.com/package/bridgebase-sdk
- Twitter: https://twitter.com/BridgeBaseAI
- Email: bridgebaseai@gmail.com

---

## License

MIT — see [LICENSE](LICENSE)

---

*Built on the Open Quantum Safe (liboqs) library. ML-KEM-768 is standardized by NIST as FIPS 203.*
