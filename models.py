"""
Pydantic models for the PQC Gateway API.
"""

from typing import Any
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Shared
# ---------------------------------------------------------------------------

class AgentPassport(BaseModel):
    """Public record stored in the on-chain / DB registry."""
    agent_id: str
    public_key: str = Field(..., description="Base64-encoded ML-KEM-768 public key")
    metadata: dict[str, Any] = Field(default_factory=dict)
    registered_at: str
    reputation_score: int = 0


# ---------------------------------------------------------------------------
# /register
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    agent_id: str = Field(..., example="solana-swap-agent-001")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        example={"owner": "alice.sol", "capabilities": ["swap", "transfer"]},
    )


class RegisterResponse(BaseModel):
    agent_id: str
    public_key: str
    private_key_plaintext: str = Field(
        ...,
        description="ONE-TIME: store this securely. Not persisted by the gateway.",
    )
    algorithm: str
    message: str


# ---------------------------------------------------------------------------
# /challenge
# ---------------------------------------------------------------------------

class ChallengeRequest(BaseModel):
    agent_id: str = Field(..., example="solana-swap-agent-001")


class ChallengeResponse(BaseModel):
    challenge_id: str
    ciphertext: str = Field(..., description="Base64 ML-KEM-768 ciphertext — decapsulate with your private key")
    algorithm: str
    expires_in_seconds: int
    instructions: str


# ---------------------------------------------------------------------------
# /verify
# ---------------------------------------------------------------------------

class VerifyRequest(BaseModel):
    challenge_id: str
    shared_secret_b64: str = Field(
        ...,
        description="Base64 shared secret recovered by decapsulating the challenge ciphertext",
    )


class VerifyResponse(BaseModel):
    agent_id: str
    verified: bool
    reputation_score: int
    session_token: str
    message: str
