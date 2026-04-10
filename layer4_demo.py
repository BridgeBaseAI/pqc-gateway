"""
BridgeBase — Layer 4 Demo
Tests full PQC handshake + Solana transaction gating
Run: python layer4_demo.py
"""

import asyncio
import httpx

GATEWAY = "https://pqc-gateway-production.up.railway.app"
AGENT_ID = "solana-trader-001"

async def run():
    print("=" * 55)
    print("  BRIDGEBASE — LAYER 4: TRANSACTION GATING DEMO")
    print("=" * 55)

    async with httpx.AsyncClient(timeout=30) as c:

        # 1. Register
        print("\n[1/5] Registering agent...")
        r = await c.post(f"{GATEWAY}/register", json={
            "agent_id": AGENT_ID,
            "metadata": {"type": "trading_bot", "chain": "solana"}
        })
        if r.status_code == 409:
            print(f"  ℹ  Agent already exists — continuing")
        else:
            r.raise_for_status()
            priv = r.json()["private_key_plaintext"]
            print(f"  ✓ Registered. Private key: {priv[:24]}...")
            # Save for next steps
            with open("agent_key.txt", "w") as f:
                f.write(priv)

        # Load private key
        try:
            with open("agent_key.txt") as f:
                priv = f.read().strip()
        except FileNotFoundError:
            print("  ✗ Run again — agent_key.txt not found")
            return

        # 2. Challenge
        print("\n[2/5] Requesting PQC challenge...")
        r = await c.post(f"{GATEWAY}/challenge", json={"agent_id": AGENT_ID})
        r.raise_for_status()
        ch = r.json()
        print(f"  ✓ Challenge: {ch['challenge_id'][:20]}...")

        # 3. Solve
        print("\n[3/5] Decapsulating ML-KEM-768 ciphertext...")
        r = await c.post(f"{GATEWAY}/dev/solve", json={
            "private_key_b64": priv,
            "ciphertext_b64": ch["ciphertext"]
        })
        r.raise_for_status()
        secret = r.json()["shared_secret_b64"]
        print(f"  ✓ Secret recovered")

        # 4. Verify → get token
        print("\n[4/5] Verifying identity...")
        r = await c.post(f"{GATEWAY}/verify", json={
            "agent_id": AGENT_ID,
            "challenge_id": ch["challenge_id"],
            "shared_secret_b64": secret
        })
        r.raise_for_status()
        v = r.json()
        token = v["session_token"]
        print(f"  ✓ Verified! Token: {token[:24]}...")
        print(f"  ✓ Reputation: {v['reputation_score']}")

        # 5. Validate token (transaction gate)
        print("\n[5/5] Requesting gateway clearance for transaction...")
        r = await c.post(f"{GATEWAY}/validate-token", json={
            "agent_id": AGENT_ID,
            "session_token": token
        })
        r.raise_for_status()
        gate = r.json()
        print(f"  ✓ {gate['message']}")
        print(f"  ✓ TX #{gate['tx_count']} authorized")

        # Bonus: blocked attempt
        print("\n[BONUS] Testing blocked transaction (bad token)...")
        r = await c.post(f"{GATEWAY}/validate-token", json={
            "agent_id": AGENT_ID,
            "session_token": "fake-token-000"
        })
        if r.status_code == 403:
            print(f"  ✓ BLOCKED: {r.json()['detail']}")

        print("\n" + "=" * 55)
        print("  LAYER 4 COMPLETE ✓")
        print("  No valid PQC token = transaction blocked")
        print("=" * 55)

if __name__ == "__main__":
    asyncio.run(run())
