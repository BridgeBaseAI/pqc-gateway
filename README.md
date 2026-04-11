# BridgeBase SDK

**The Trust Layer for the Agentic Economy**

Quantum-safe identity and transaction gating for AI agents. Uses ML-KEM-768 (NIST FIPS 203) post-quantum cryptography.

## Install

```bash
npm install bridgebase-sdk
```

## Quick Start

```javascript
const { BridgeBaseClient } = require('bridgebase-sdk')

const client = new BridgeBaseClient()

// Register agent (run once, save private key)
const result = await client.register('my-agent-001')
const privateKey = result.privateKey  // SAVE THIS

// Authenticate (run every session)
const token = await client.authenticate('my-agent-001', privateKey)

// Gate a transaction
const cleared = await client.validateToken('my-agent-001', token)
// true = cleared, throws BridgeBaseError if blocked
```

## Why BridgeBase

- **$2.87B** in crypto hacks in 2025 — 76% from key compromises
- **Quantum computers** will break current encryption within years
- **ML-KEM-768** is the NIST FIPS 203 standard — quantum-proof today
- **No other solution** combines AI agent identity + blockchain + PQC

## API

### `new BridgeBaseClient(options?)`

| Option | Default | Description |
|---|---|---|
| `gatewayUrl` | `https://pqc-gateway-production.up.railway.app` | Gateway URL |
| `timeout` | `30000` | Request timeout in ms |

### `client.register(agentId, metadata?)`

Register a new agent. Returns `{ agentId, publicKey, privateKey, algorithm }`.

**Save the private key — it is never stored by the gateway.**

### `client.authenticate(agentId, privateKey)`

Full 3-step ML-KEM-768 handshake. Returns session token.

### `client.validateToken(agentId, sessionToken)`

Gate a transaction. Returns `true` if cleared, throws `BridgeBaseError` (403) if blocked.

### `client.getPassport(agentId)`

Returns `{ agentId, publicKey, reputationScore, registeredAt, metadata }`.

### `client.listAgents()`

Returns array of registered agent IDs.

### `client.reputation(agentId)`

Returns agent reputation score (increments on every successful handshake).

### `client.health()`

Returns `{ status, algorithm }`.

## ElizaOS Integration

```javascript
const { BridgeBaseClient } = require('bridgebase-sdk')

const bridge = new BridgeBaseClient()

// In your ElizaOS agent action:
async function secureAction(agentId, privateKey) {
  const token = await bridge.authenticate(agentId, privateKey)
  const cleared = await bridge.validateToken(agentId, token)
  if (cleared) {
    // Execute your Solana transaction
  }
}
```

## Error Handling

```javascript
const { BridgeBaseClient, BridgeBaseError } = require('bridgebase-sdk')

try {
  const cleared = await client.validateToken(agentId, token)
} catch (err) {
  if (err instanceof BridgeBaseError && err.statusCode === 403) {
    console.log('Transaction blocked — invalid token')
  }
}
```

## Links

- **Gateway:** https://pqc-gateway-production.up.railway.app
- **GitHub:** https://github.com/BridgeBaseAI/pqc-gateway
- **Docs:** https://pqc-gateway-production.up.railway.app/docs

## License

MIT
