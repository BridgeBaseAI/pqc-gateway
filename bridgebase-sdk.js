/**
 * BridgeBase JavaScript SDK
 * The Trust Layer for the Agentic Economy
 *
 * Works in: Node.js, ElizaOS, Virtuals, browser, ESM, CJS
 * No dependencies — uses built-in fetch only
 *
 * CJS:  const { BridgeBaseClient } = require('bridgebase-sdk')
 * ESM:  import { BridgeBaseClient } from 'bridgebase-sdk'
 */

'use strict'

class BridgeBaseError extends Error {
  constructor(message, statusCode = null) {
    super(message)
    this.name = 'BridgeBaseError'
    this.statusCode = statusCode
  }
}

class BridgeBaseClient {
  /**
   * @param {object} options
   * @param {string} options.gatewayUrl - BridgeBase gateway URL
   * @param {number} options.timeout    - Request timeout in ms (default 30000)
   */
  constructor(options = {}) {
    this.gatewayUrl = (options.gatewayUrl || 'https://pqc-gateway-production.up.railway.app').replace(/\/$/, '')
    this.timeout = options.timeout || 30000
  }

  async _post(path, body) {
    const url = `${this.gatewayUrl}${path}`
    let res
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeout),
      })
    } catch (err) {
      throw new BridgeBaseError(`Cannot connect to gateway: ${err.message}`)
    }
    const data = await res.json().catch(() => ({}))
    if (!res.ok) {
      const detail = data.detail || data.message || res.statusText
      throw new BridgeBaseError(`Gateway error on ${path}: ${detail}`, res.status)
    }
    return data
  }

  async _get(path) {
    const url = `${this.gatewayUrl}${path}`
    let res
    try {
      res = await fetch(url, {
        method: 'GET',
        signal: AbortSignal.timeout(this.timeout),
      })
    } catch (err) {
      throw new BridgeBaseError(`Cannot connect to gateway: ${err.message}`)
    }
    const data = await res.json().catch(() => ({}))
    if (!res.ok) {
      const detail = data.detail || data.message || res.statusText
      throw new BridgeBaseError(`Gateway error on ${path}: ${detail}`, res.status)
    }
    return data
  }

  async health() {
    return this._get('/health')
  }

  async register(agentId, metadata = {}) {
    const data = await this._post('/register', { agent_id: agentId, metadata })
    return {
      agentId: data.agent_id,
      publicKey: data.public_key,
      privateKey: data.private_key_plaintext,
      algorithm: data.algorithm,
    }
  }

  async authenticate(agentId, privateKey) {
    const challenge = await this._post('/challenge', { agent_id: agentId })
    const solved = await this._post('/dev/solve', {
      private_key_b64: privateKey,
      ciphertext_b64: challenge.ciphertext,
    })
    const verified = await this._post('/verify', {
      agent_id: agentId,
      challenge_id: challenge.challenge_id,
      shared_secret_b64: solved.shared_secret_b64,
    })
    return verified.session_token
  }

  async validateToken(agentId, sessionToken) {
    const result = await this._post('/validate-token', {
      agent_id: agentId,
      session_token: sessionToken,
    })
    return result.cleared === true
  }

  async getPassport(agentId) {
    const data = await this._get(`/passport/${agentId}`)
    return {
      agentId: data.agent_id,
      publicKey: data.public_key,
      reputationScore: data.reputation_score,
      registeredAt: data.registered_at,
      metadata: data.metadata,
    }
  }

  async listAgents() {
    const data = await this._get('/agents')
    return data.agents
  }

  async reputation(agentId) {
    const passport = await this.getPassport(agentId)
    return passport.reputationScore
  }
}

// Dual CJS + ESM export
module.exports = { BridgeBaseClient, BridgeBaseError }
module.exports.default = { BridgeBaseClient, BridgeBaseError }
module.exports.BridgeBaseClient = BridgeBaseClient
module.exports.BridgeBaseError = BridgeBaseError
