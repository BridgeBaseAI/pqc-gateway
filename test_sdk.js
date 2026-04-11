/**
 * BridgeBase JS SDK — Live Test
 * Run: node test_sdk.js
 */

const { BridgeBaseClient, BridgeBaseError } = require('./bridgebase-sdk')
const fs = require('fs')

const AGENT_ID = 'js-sdk-agent-001'
const KEY_FILE = 'js_agent_key.txt'

async function run() {
  console.log('='.repeat(55))
  console.log('  BRIDGEBASE JS SDK — LIVE TEST')
  console.log('='.repeat(55))

  const client = new BridgeBaseClient()

  // 1. Health
  console.log('\n[1/6] health()')
  const h = await client.health()
  if (h.status !== 'ok') throw new Error('Health check failed')
  console.log(`  ✓ Gateway online — algorithm: ${h.algorithm}`)

  // 2. Register
  console.log(`\n[2/6] register('${AGENT_ID}')`)
  let privateKey
  try {
    const result = await client.register(AGENT_ID, { type: 'js_sdk_test' })
    privateKey = result.privateKey
    fs.writeFileSync(KEY_FILE, privateKey)
    console.log(`  ✓ Registered. Key saved to ${KEY_FILE}`)
    console.log(`  ✓ Public key: ${result.publicKey.slice(0, 32)}...`)
  } catch (err) {
    if (err.statusCode === 409) {
      console.log(`  ℹ  Already registered — loading saved key`)
      privateKey = fs.readFileSync(KEY_FILE, 'utf8').trim()
    } else {
      throw err
    }
  }

  // 3. Authenticate
  console.log(`\n[3/6] authenticate('${AGENT_ID}')`)
  const token = await client.authenticate(AGENT_ID, privateKey)
  if (!token || token.length < 10) throw new Error('Token too short')
  console.log(`  ✓ Session token: ${token.slice(0, 24)}...`)

  // 4. Validate token
  console.log(`\n[4/6] validateToken()`)
  const cleared = await client.validateToken(AGENT_ID, token)
  if (!cleared) throw new Error('Token validation failed')
  console.log(`  ✓ Transaction cleared`)

  // 5. Get passport
  console.log(`\n[5/6] getPassport('${AGENT_ID}')`)
  const passport = await client.getPassport(AGENT_ID)
  console.log(`  ✓ Reputation: ${passport.reputationScore}`)
  console.log(`  ✓ Registered at: ${passport.registeredAt}`)

  // 6. List agents
  console.log(`\n[6/6] listAgents()`)
  const agents = await client.listAgents()
  if (!agents.includes(AGENT_ID)) throw new Error(`${AGENT_ID} not in list`)
  console.log(`  ✓ ${agents.length} agent(s) registered`)
  console.log(`  ✓ ${AGENT_ID} confirmed in registry`)

  // Blocked token test
  console.log(`\n[BONUS] Blocked token test`)
  try {
    await client.validateToken(AGENT_ID, 'fake-token-xyz')
    console.log('  ✗ Should have been blocked!')
  } catch (err) {
    if (err.statusCode === 403) {
      console.log(`  ✓ Correctly blocked: ${err.message}`)
    } else {
      throw err
    }
  }

  console.log('\n' + '='.repeat(55))
  console.log('  ALL JS SDK TESTS PASSED ✓')
  console.log('='.repeat(55))
}

run().catch(err => {
  console.error('\n✗ TEST FAILED:', err.message)
  process.exit(1)
})
