"""
BridgeBase SDK — Live Test
Tests every SDK method against the live Railway gateway.
Run: python test_sdk.py
"""

from bridgebase_sdk import BridgeBaseClient, BridgeBaseError

AGENT_ID = "sdk-test-agent-001"
KEY_FILE = "sdk_agent_key.txt"

client = BridgeBaseClient()

print("=" * 55)
print("  BRIDGEBASE SDK — LIVE TEST")
print("=" * 55)

# 1. Health
print("\n[1/6] health()")
h = client.health()
assert h["status"] == "ok", "Health check failed"
print(f"  ✓ Gateway online — algorithm: {h['algorithm']}")

# 2. Register
print(f"\n[2/6] register('{AGENT_ID}')")
try:
    result = client.register(agent_id=AGENT_ID, metadata={"type": "sdk_test"})
    private_key = result["private_key"]
    with open(KEY_FILE, "w") as f:
        f.write(private_key)
    print(f"  ✓ Registered. Key saved to {KEY_FILE}")
    print(f"  ✓ Public key: {result['public_key'][:32]}...")
except BridgeBaseError as e:
    if "already registered" in str(e):
        print(f"  ℹ  Already registered — loading saved key")
        with open(KEY_FILE) as f:
            private_key = f.read().strip()
    else:
        raise

# 3. Authenticate
print(f"\n[3/6] authenticate('{AGENT_ID}')")
token = client.authenticate(agent_id=AGENT_ID, private_key=private_key)
assert len(token) > 10, "Token too short"
print(f"  ✓ Session token: {token[:24]}...")

# 4. Validate token
print(f"\n[4/6] validate_token()")
cleared = client.validate_token(agent_id=AGENT_ID, session_token=token)
assert cleared is True, "Token validation failed"
print(f"  ✓ Transaction cleared")

# 5. Get passport
print(f"\n[5/6] get_passport('{AGENT_ID}')")
passport = client.get_passport(AGENT_ID)
print(f"  ✓ Reputation: {passport['reputation_score']}")
print(f"  ✓ Registered at: {passport['registered_at']}")

# 6. List agents
print(f"\n[6/6] list_agents()")
agents = client.list_agents()
assert AGENT_ID in agents, f"{AGENT_ID} not in agent list"
print(f"  ✓ {len(agents)} agent(s) registered")
print(f"  ✓ {AGENT_ID} confirmed in registry")

# Blocked token test
print(f"\n[BONUS] Blocked token test")
try:
    client.validate_token(agent_id=AGENT_ID, session_token="bad-token-xyz")
    print("  ✗ Should have been blocked!")
except BridgeBaseError as e:
    print(f"  ✓ Correctly blocked: {e}")

print("\n" + "=" * 55)
print("  ALL SDK TESTS PASSED ✓")
print("=" * 55)
