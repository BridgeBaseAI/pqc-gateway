/**
 * BridgeBase JavaScript SDK
 * The Trust Layer for the Agentic Economy
 * 
 * Works in: Node.js, ElizaOS, Virtuals, browser
 * No dependencies — uses built-in fetch only
 * 
 * Usage:
 *   const { BridgeBaseClient } = require('./bridgebase-sdk')
 *   const client = new BridgeBaseClient()
 *   const token = await client.authenticate('my-agent', privateKey)
 *   const cleared = await client.validateToken('my-agent', token)
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

  // -------------------------------------------------------------------------
  // Internal
  // -------------------------------------------------------------------------

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

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /**
   * Check gateway health
   * @returns {{ status: string, algorithm: string }}
   */
  async health() {
    return this._get('/health')
  }

  /**
   * Register a new agent — run once, save the private key
   * @param {string} agentId
   * @param {object} metadata
   * @returns {{ agentId, publicKey, privateKey, algorithm }}
   */
  async register(agentId, metadata = {}) {
    const data = await this._post('/register', {
      agent_id: agentId,
      metadata,
    })
    return {
      agentId: data.agent_id,
      publicKey: data.public_key,
      privateKey: data.private_key_plaintext,
      algorithm: data.algorithm,
    }
  }

  /**
   * Full 3-step PQC handshake — returns session token
   * Handles challenge + solve + verify automatically
   * @param {string} agentId
   * @param {string} privateKey - base64 ML-KEM-768 private key from register()
   * @returns {string} session token
   */
  async authenticate(agentId, privateKey) {
    // Step 1: Request challenge
    const challenge = await this._post('/challenge', { agent_id: agentId })

    // Step 2: Solve (decapsulate via gateway)
    const solved = await this._post('/dev/solve', {
      private_key_b64: privateKey,
      ciphertext_b64: challenge.ciphertext,
    })

    // Step 3: Verify → get session token
    const verified = await this._post('/verify', {
      agent_id: agentId,
      challenge_id: challenge.challenge_id,
      shared_secret_b64: solved.shared_secret_b64,
    })

    return verified.session_token
  }

  /**
   * Validate session token before a transaction
   * @param {string} agentId
   * @param {string} sessionToken
   * @returns {boolean} true if cleared
   * @throws {BridgeBaseError} if blocked (403)
   */
  async validateToken(agentId, sessionToken) {
    const result = await this._post('/validate-token', {
      agent_id: agentId,
      session_token: sessionToken,
    })
    return result.cleared === true
  }

  /**
   * Fetch agent public passport
   * @param {string} agentId
   * @returns {{ agentId, publicKey, reputationScore, registeredAt }}
   */
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

  /**
   * List all registered agent IDs
   * @returns {string[]}
   */
  async listAgents() {
    const data = await this._get('/agents')
    return data.agents
  }

  /**
   * Get agent reputation score
   * @param {string} agentId
   * @returns {number}
   */
  async reputation(agentId) {
    const passport = await this.getPassport(agentId)
    return passport.reputationScore
  }
}

module.exports = { BridgeBaseClient, BridgeBaseError }
