"""
BridgeBase Python SDK
The Trust Layer for the Agentic Economy

Usage:
    from bridgebase_sdk import BridgeBaseClient

    client = BridgeBaseClient(gateway_url="https://pqc-gateway-production.up.railway.app")

    # Register a new agent (run once, save private key)
    result = client.register(agent_id="my-agent-001")
    private_key = result["private_key"]  # SAVE THIS

    # Authenticate (run every session)
    token = client.authenticate(agent_id="my-agent-001", private_key=private_key)

    # Gate a transaction
    cleared = client.validate_token(agent_id="my-agent-001", session_token=token)
"""

import httpx
from typing import Optional


class BridgeBaseError(Exception):
    """Raised when the gateway returns an error."""
    pass


class BridgeBaseClient:
    """
    Synchronous client for the BridgeBase PQC Gateway.
    No dependencies beyond httpx.
    """

    def __init__(
        self,
        gateway_url: str = "https://pqc-gateway-production.up.railway.app",
        timeout: int = 30,
    ):
        self.gateway_url = gateway_url.rstrip("/")
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _post(self, path: str, body: dict) -> dict:
        url = f"{self.gateway_url}{path}"
        try:
            r = httpx.post(url, json=body, timeout=self.timeout)
        except httpx.ConnectError:
            raise BridgeBaseError(f"Cannot connect to gateway at {self.gateway_url}")
        if not r.is_success:
            detail = r.json().get("detail", r.text) if r.content else r.status_code
            raise BridgeBaseError(f"Gateway error on {path}: {detail}")
        return r.json()

    def _get(self, path: str) -> dict:
        url = f"{self.gateway_url}{path}"
        try:
            r = httpx.get(url, timeout=self.timeout)
        except httpx.ConnectError:
            raise BridgeBaseError(f"Cannot connect to gateway at {self.gateway_url}")
        if not r.is_success:
            detail = r.json().get("detail", r.text) if r.content else r.status_code
            raise BridgeBaseError(f"Gateway error on {path}: {detail}")
        return r.json()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def health(self) -> dict:
        """Check if the gateway is online."""
        return self._get("/health")

    def register(self, agent_id: str, metadata: Optional[dict] = None) -> dict:
        """
        Register a new agent. Returns private key — save it, never stored again.

        Returns:
            {
                "agent_id": str,
                "public_key": str,
                "private_key": str,   # base64 ML-KEM-768 private key
                "algorithm": str,
            }
        """
        body = {"agent_id": agent_id, "metadata": metadata or {}}
        data = self._post("/register", body)
        return {
            "agent_id": data["agent_id"],
            "public_key": data["public_key"],
            "private_key": data["private_key_plaintext"],
            "algorithm": data["algorithm"],
        }

    def authenticate(self, agent_id: str, private_key: str) -> str:
        """
        Full 3-step PQC handshake. Returns session token on success.

        Steps handled automatically:
            1. Request challenge from gateway
            2. Decapsulate ciphertext using private key
            3. Verify with gateway → receive session token

        Args:
            agent_id:    Your registered agent ID
            private_key: Base64 ML-KEM-768 private key from register()

        Returns:
            session_token (str) — pass this to validate_token() before transactions
        """
        # Step 1: Challenge
        ch = self._post("/challenge", {"agent_id": agent_id})

        # Step 2: Solve (decapsulate via gateway dev endpoint)
        solved = self._post("/dev/solve", {
            "private_key_b64": private_key,
            "ciphertext_b64": ch["ciphertext"],
        })

        # Step 3: Verify
        verified = self._post("/verify", {
            "agent_id": agent_id,
            "challenge_id": ch["challenge_id"],
            "shared_secret_b64": solved["shared_secret_b64"],
        })

        return verified["session_token"]

    def validate_token(self, agent_id: str, session_token: str) -> bool:
        """
        Check if a session token is valid before executing a transaction.

        Returns:
            True if cleared, raises BridgeBaseError if blocked.
        """
        result = self._post("/validate-token", {
            "agent_id": agent_id,
            "session_token": session_token,
        })
        return result["cleared"]

    def get_passport(self, agent_id: str) -> dict:
        """Fetch an agent's public passport (public key + reputation)."""
        return self._get(f"/passport/{agent_id}")

    def list_agents(self) -> list:
        """List all registered agent IDs."""
        return self._get("/agents")["agents"]

    def reputation(self, agent_id: str) -> int:
        """Get an agent's current reputation score."""
        passport = self.get_passport(agent_id)
        return passport["reputation_score"]
