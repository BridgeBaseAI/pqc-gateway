"""
BridgeBase — Session Token Store
Validates PQC-issued tokens before allowing Solana transactions.
"""

import hmac
import time
import secrets
from typing import Optional

# In-memory token store
_active_tokens: dict = {}
TOKEN_TTL = 3600  # 1 hour


def issue_token(agent_id: str, reputation: int) -> str:
    token = secrets.token_hex(32)
    _active_tokens[token] = {
        "agent_id": agent_id,
        "issued_at": time.time(),
        "reputation": reputation,
        "tx_count": 0,
    }
    return token


def validate_token(agent_id: str, token: str) -> dict:
    if token not in _active_tokens:
        raise PermissionError("Invalid or expired session token")

    data = _active_tokens[token]

    if time.time() - data["issued_at"] > TOKEN_TTL:
        del _active_tokens[token]
        raise PermissionError("Session token expired")

    if not hmac.compare_digest(data["agent_id"], agent_id):
        raise PermissionError("Token agent_id mismatch")

    _active_tokens[token]["tx_count"] += 1

    return {
        "agent_id": agent_id,
        "reputation": data["reputation"],
        "tx_count": _active_tokens[token]["tx_count"],
        "valid": True,
    }


def revoke_token(token: str):
    _active_tokens.pop(token, None)
