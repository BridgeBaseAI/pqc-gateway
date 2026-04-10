# 🌉 BridgeBase
**The Trust Layer for the Agentic Economy**

[![Live Demo](https://img.shields.io/badge/Live-Railway-00ff00?style=for-the-badge)](https://pqc-gateway-production.up.railway.app)
[![SDK](https://img.shields.io/badge/SDK-Python-blue?style=for-the-badge)](https://github.com/BridgeBaseAI/pqc-gateway)
[![Algorithm](https://img.shields.io/badge/PQC-ML--KEM--768-green?style=for-the-badge)](https://csrc.nist.gov/pubs/fips/203/ipd)

## 🌐 Overview
BridgeBase is a **Quantum-Safe AI Agent Gateway** designed to secure the "Agentic Economy." As AI agents increasingly manage treasury wallets and execute on-chain swaps, standard ECDSA/Ed25519 signatures are vulnerable to future quantum threats. 

BridgeBase introduces the **"Quantum Tax"**: a mandatory Post-Quantum Cryptographic (PQC) handshake that AI agents must pass before they are authorized to sign or broadcast blockchain transactions.

## 🛠 The Architecture
BridgeBase sits between the **AI Agent** and the **Blockchain (Solana)**.

1. **Identity:** Agents register with a NIST-standard ML-KEM-768 public key.
2. **Challenge:** When an agent wants to act, BridgeBase issues a PQC ciphertext challenge.
3. **Verification:** The agent must decapsulate the secret using its private PQC key.
4. **Gating:** Once verified, the gateway issues a 3600s session token. No token = No transaction.

---

## 🚀 Quick Start (Python SDK)

Secure your agent in seconds.

### Installation
```bash
# Clone the repository
git clone [https://github.com/BridgeBaseAI/pqc-gateway.git](https://github.com/BridgeBaseAI/pqc-gateway.git)
cd pqc-gateway
pip install -r requirements.txt
```

### Usage
```python
from bridgebase_sdk import BridgeBaseClient

# Connect to the live Trust Layer
client = BridgeBaseClient(gateway_url="[https://pqc-gateway-production.up.railway.app](https://pqc-gateway-production.up.railway.app)")

# 1. PQC Authentication (Full Handshake)
session_token = client.authenticate(
    agent_id="solana-trader-001", 
    private_key="YOUR_PQC_PRIVATE_KEY"
)

# 2. Execute a Gated Transaction
if client.validate_token("solana-trader-001", session_token):
    print("Agent verified. Transaction authorized.")
```

---

## 🏛 Technical Stack
- **PQC Algorithm:** ML-KEM-768 (NIST FIPS 203) via `liboqs`.
- **Backend:** FastAPI (Python 3.14).
- **Blockchain:** Solana Devnet (Transaction Gating + On-chain Reputation).
- **Infrastructure:** Docker + Railway (24/7 Global Availability).

## 📊 Market Context
- **The Problem:** 76% of crypto hacks in 2025 resulted from key compromises. AI agents represent a new, massive attack surface.
- **The Solution:** BridgeBase adds a quantum-hardened identity layer, ensuring that even if a traditional wallet key is leaked, the agent must still pass a PQC handshake to move funds.

## 🛣 Roadmap
- [x] Layer 1-5: Live PQC Gateway & Cloud Infrastructure
- [x] Layer 6: Python SDK
- [x] Layer 7: Solana On-Chain Reputation Logs
- [ ] Layer 8: JavaScript/TypeScript SDK (for ElizaOS integration)
- [ ] Layer 9: Enterprise API Key Management

---

**BridgeBase** — *Securing the agents of today against the threats of tomorrow.*

Contact: [bridgebaseai@gmail.com](mailto:bridgebaseai@gmail.com)
