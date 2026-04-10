"""
BridgeBase — Layer 7: On-Chain Reputation
Run: python layer7_reputation.py
"""

import json
import time
import hashlib
import urllib.request
from datetime import datetime, timezone

from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.hash import Hash
from solders.transaction import Transaction
from solders.message import Message
from solders.instruction import Instruction, AccountMeta
from solana.rpc.api import Client
from solana.rpc.types import TxOpts

from bridgebase_sdk import BridgeBaseClient, BridgeBaseError

DEVNET_URL = "https://api.devnet.solana.com"
GATEWAY_URL = "https://pqc-gateway-production.up.railway.app"
MEMO_PROGRAM_ID = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
WALLET_FILE = "gateway_wallet.json"


def rpc_call(method: str, params: list) -> dict:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        DEVNET_URL, data=payload,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


class OnChainReputation:

    def __init__(self):
        self.client = Client(DEVNET_URL)
        # Persist wallet so address stays the same across runs
        try:
            with open(WALLET_FILE) as f:
                secret = bytes(json.load(f))
            self.wallet = Keypair.from_bytes(secret)
            print(f"  [wallet] Loaded existing wallet")
        except FileNotFoundError:
            self.wallet = Keypair()
            with open(WALLET_FILE, "w") as f:
                json.dump(list(bytes(self.wallet)), f)
            print(f"  [wallet] Created new wallet")
        self.funded = False

    def check_balance(self) -> float:
        bal = rpc_call("getBalance", [str(self.wallet.pubkey())])
        return bal["result"]["value"] / 1e9

    def request_airdrop(self) -> bool:
        print(f"  [wallet] Address: {self.wallet.pubkey()}")

        # Check if already funded from manual faucet
        sol = self.check_balance()
        if sol > 0:
            print(f"  [wallet] Already funded: {sol:.4f} SOL")
            self.funded = True
            return True

        print(f"  [wallet] Requesting airdrop...")
        try:
            data = rpc_call("requestAirdrop", [str(self.wallet.pubkey()), 1_000_000_000])
            if "error" in data:
                print(f"  [wallet] Airdrop error: {data['error']['message'][:60]}")
                print(f"  [wallet] Fund manually at: https://faucet.solana.com")
                print(f"  [wallet] Address: {self.wallet.pubkey()}")
                return False

            print(f"  [wallet] Airdrop sent. Waiting 10 seconds...")
            time.sleep(10)
            sol = self.check_balance()
            print(f"  [wallet] Balance: {sol:.4f} SOL")
            self.funded = sol > 0
            return self.funded
        except Exception as e:
            print(f"  [wallet] Error: {e}")
            return False

    def write_reputation(self, agent_id: str, reputation: int, event: str = "verify") -> dict:
        if not self.funded:
            raise Exception("Wallet not funded.")

        memo_text = json.dumps({
            "p": "BRIDGEBASE",
            "a": agent_id,
            "r": reputation,
            "e": event,
            "t": int(datetime.now(timezone.utc).timestamp()),
        }, separators=(",", ":"))

        bh_data = rpc_call("getLatestBlockhash", [{"commitment": "confirmed"}])
        blockhash = Hash.from_string(bh_data["result"]["value"]["blockhash"])

        memo_ix = Instruction(
            program_id=MEMO_PROGRAM_ID,
            accounts=[AccountMeta(pubkey=self.wallet.pubkey(), is_signer=True, is_writable=False)],
            data=memo_text.encode("utf-8"),
        )
        msg = Message.new_with_blockhash(
            instructions=[memo_ix],
            payer=self.wallet.pubkey(),
            blockhash=blockhash,
        )
        tx = Transaction([self.wallet], msg, blockhash)
        opts = TxOpts(skip_preflight=False, preflight_commitment="confirmed")
        result = self.client.send_transaction(tx, opts=opts)
        sig = str(result.value)

        return {
            "signature": sig,
            "agent_id": agent_id,
            "reputation": reputation,
            "memo": memo_text,
            "explorer": f"https://explorer.solana.com/tx/{sig}?cluster=devnet",
        }


class ReputationLog:
    def __init__(self, path="reputation_log.json"):
        self.path = path
        try:
            with open(self.path) as f:
                self.entries = json.load(f)
        except FileNotFoundError:
            self.entries = []

    def _save(self):
        with open(self.path, "w") as f:
            json.dump(self.entries, f, indent=2)

    def _hash(self, entry):
        return hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()[:16]

    def append(self, agent_id, reputation, event, tx_sig=None):
        prev_hash = self.entries[-1]["hash"] if self.entries else "genesis"
        entry = {
            "seq": len(self.entries) + 1,
            "agent_id": agent_id,
            "reputation": reputation,
            "event": event,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tx_signature": tx_sig or "local-only",
            "prev_hash": prev_hash,
        }
        entry["hash"] = self._hash(entry)
        self.entries.append(entry)
        self._save()
        return entry

    def verify_chain(self):
        for i, entry in enumerate(self.entries):
            expected = self.entries[i-1]["hash"] if i > 0 else "genesis"
            if entry["prev_hash"] != expected:
                return False
        return True


def run_demo():
    print("=" * 55)
    print("  BRIDGEBASE — LAYER 7: ON-CHAIN REPUTATION")
    print("=" * 55)

    gateway = BridgeBaseClient(gateway_url=GATEWAY_URL)
    log = ReputationLog()
    chain = OnChainReputation()

    print("\n[1/5] Setting up Solana devnet wallet...")
    funded = chain.request_airdrop()
    if not funded:
        print("\n  ACTION REQUIRED:")
        print(f"  1. Go to https://faucet.solana.com")
        print(f"  2. Paste: {chain.wallet.pubkey()}")
        print(f"  3. Click Confirm Airdrop")
        print(f"  4. Run this script again")
        return

    AGENT_ID = "reputation-agent-001"
    KEY_FILE = "rep_agent_key.txt"

    print(f"\n[2/5] Registering agent: {AGENT_ID}")
    try:
        result = gateway.register(agent_id=AGENT_ID, metadata={"layer": 7})
        private_key = result["private_key"]
        with open(KEY_FILE, "w") as f:
            f.write(private_key)
        print(f"  ✓ Registered")
    except BridgeBaseError as e:
        if "already registered" in str(e):
            print(f"  ℹ  Already registered")
            with open(KEY_FILE) as f:
                private_key = f.read().strip()
        else:
            raise

    print(f"\n[3/5] PQC handshake...")
    token = gateway.authenticate(agent_id=AGENT_ID, private_key=private_key)
    print(f"  ✓ Token: {token[:24]}...")

    passport = gateway.get_passport(AGENT_ID)
    reputation = passport["reputation_score"]
    print(f"\n[4/5] Current reputation: {reputation}")

    print(f"\n[5/5] Writing reputation to Solana devnet...")
    try:
        tx = chain.write_reputation(AGENT_ID, reputation, "verify")
        print(f"  ✓ Transaction confirmed!")
        print(f"  ✓ Signature: {tx['signature'][:32]}...")
        print(f"  ✓ Explorer:  {tx['explorer']}")
        entry = log.append(AGENT_ID, reputation, "verify", tx["signature"])
        print(f"  ✓ Log entry #{entry['seq']} — hash: {entry['hash']}")
    except Exception as e:
        print(f"  ✗ On-chain failed: {e}")
        entry = log.append(AGENT_ID, reputation, "verify")
        print(f"  ✓ Local log entry #{entry['seq']}")

    print(f"\n[VERIFY] Chain integrity: {log.verify_chain()}")
    print(f"  ✓ Total entries: {len(log.entries)}")
    print("\n" + "=" * 55)
    print("  LAYER 7 COMPLETE ✓")
    print("=" * 55)


if __name__ == "__main__":
    run_demo()