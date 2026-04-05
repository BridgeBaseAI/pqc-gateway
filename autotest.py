"""
PQC Gateway — Full Automated Test
Runs the complete handshake in one command:
  1. Register agent
  2. Get challenge
  3. Solve challenge with private key
  4. Verify and get session token
"""

import oqs
import base64
import requests
import json

GATEWAY = "http://localhost:8000"
AGENT_ID = "auto-test-agent"


def separator(title):
    print(f"\n{'='*50}")
    print(f"  {title}")
    print('='*50)


# ── STEP 1: Register ──────────────────────────────────
separator("STEP 1: Registering Agent")

resp = requests.post(f"{GATEWAY}/register", json={
    "agent_id": AGENT_ID,
    "metadata": {"owner": "student-dev", "purpose": "testing"}
})

if resp.status_code == 409:
    print(f"Agent '{AGENT_ID}' already exists — skipping registration")
    print("(Delete registry.db in Docker volume to start fresh)")
    private_key_b64 = None
elif resp.status_code == 201:
    data = resp.json()
    private_key_b64 = data["private_key_plaintext"]
    print(f"Agent ID  : {data['agent_id']}")
    print(f"Algorithm : {data['algorithm']}")
    print(f"Public Key: {data['public_key'][:40]}...")
    print(f"Private Key (first 40 chars): {private_key_b64[:40]}...")
    print("\n⚠️  In production: save private key to encrypted storage!")
else:
    print(f"Registration failed: {resp.status_code} {resp.text}")
    exit(1)


# ── If agent already existed, we can't proceed without the private key ──
if private_key_b64 is None:
    print("\nCannot complete handshake without private key.")
    print("Run this command to reset and start fresh:")
    print("  docker compose down -v && docker compose up")
    exit(0)


# ── STEP 2: Get Challenge ─────────────────────────────
separator("STEP 2: Requesting PQC Challenge")

resp = requests.post(f"{GATEWAY}/challenge", json={"agent_id": AGENT_ID})
data = resp.json()

challenge_id   = data["challenge_id"]
ciphertext_b64 = data["ciphertext"]

print(f"Challenge ID : {challenge_id}")
print(f"Ciphertext   : {ciphertext_b64[:40]}...")
print(f"Expires in   : {data['expires_in_seconds']} seconds")


# ── STEP 3: Solve Challenge Locally ──────────────────
separator("STEP 3: Solving Challenge with Private Key")

private_key = base64.b64decode(private_key_b64)
ciphertext  = base64.b64decode(ciphertext_b64)

with oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key) as kem:
    shared_secret = kem.decap_secret(ciphertext)

shared_secret_b64 = base64.b64encode(shared_secret).decode()
print(f"Shared secret recovered: {shared_secret_b64[:40]}...")
print("Private key never left this machine ✓")


# ── STEP 4: Verify ───────────────────────────────────
separator("STEP 4: Verifying with Gateway")

resp = requests.post(f"{GATEWAY}/verify", json={
    "challenge_id": challenge_id,
    "shared_secret_b64": shared_secret_b64
})
data = resp.json()

print(f"Verified         : {data['verified']}")
print(f"Reputation Score : {data['reputation_score']}")
print(f"Session Token    : {data['session_token'][:40]}...")


# ── RESULT ───────────────────────────────────────────
separator("RESULT")

if data["verified"]:
    print("""
  ✅ PQC HANDSHAKE COMPLETE

  What just happened:
  - Gateway encrypted a secret using your PUBLIC key
  - Only your PRIVATE key could decrypt it
  - You proved identity without sending your private key
  - A quantum computer cannot break this handshake

  Your agent is now trusted by the gateway.
  Reputation score goes up every successful verify.
""")
else:
    print("❌ Handshake failed — check your gateway logs")
