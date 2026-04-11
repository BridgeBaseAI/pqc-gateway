"""
BridgeBase — Security Layer
Rate limiting + API key authentication
"""

import time
import hmac
import hashlib
import secrets
import os
from collections import defaultdict
from fastapi import Request, HTTPException

# ---------------------------------------------------------------------------
# Rate Limiter — in-memory, per IP
# ---------------------------------------------------------------------------

# Stores: { ip: [timestamp, timestamp, ...] }
_rate_store: dict = defaultdict(list)

RATE_LIMITS = {
    "/register":       (5,  3600),   # 5 per hour
    "/challenge":      (30, 60),     # 30 per minute
    "/verify":         (30, 60),     # 30 per minute
    "/validate-token": (60, 60),     # 60 per minute
    "/dev/solve":      (30, 60),     # 30 per minute
}


def check_rate_limit(request: Request):
    """
    Call this at the top of any endpoint.
    Raises 429 if IP has exceeded the rate limit for this path.
    """
    ip = request.client.host
    path = request.url.path

    if path not in RATE_LIMITS:
        return  # no limit for this path

    max_calls, window_seconds = RATE_LIMITS[path]
    now = time.time()
    key = f"{ip}:{path}"

    # Remove expired timestamps
    _rate_store[key] = [t for t in _rate_store[key] if now - t < window_seconds]

    if len(_rate_store[key]) >= max_calls:
        retry_after = int(window_seconds - (now - _rate_store[key][0]))
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )

    _rate_store[key].append(now)


# ---------------------------------------------------------------------------
# API Key System
# ---------------------------------------------------------------------------

# Master admin key — set via env var, random default for safety
_ADMIN_KEY = os.environ.get("BRIDGEBASE_ADMIN_KEY", secrets.token_hex(32))

# In-memory API key store: { key_hash: { tier, agent_id, created_at } }
_api_keys: dict = {}

# Free tier limits
TIER_LIMITS = {
    "free":       {"agents": 3,    "auths_per_month": 1000},
    "pro":        {"agents": 100,  "auths_per_month": 50000},
    "business":   {"agents": 1000, "auths_per_month": 500000},
    "enterprise": {"agents": -1,   "auths_per_month": -1},  # unlimited
}


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def generate_api_key(tier: str = "free", label: str = "") -> dict:
    """Generate a new API key for a given tier."""
    key = f"bb_{tier}_{secrets.token_hex(24)}"
    key_hash = _hash_key(key)
    _api_keys[key_hash] = {
        "tier": tier,
        "label": label,
        "created_at": time.time(),
        "auth_count": 0,
    }
    return {
        "api_key": key,
        "tier": tier,
        "limits": TIER_LIMITS[tier],
        "message": "Store this key securely — it will not be shown again.",
    }


def validate_api_key(api_key: str) -> dict:
    """Validate an API key. Returns key data or raises 401."""
    key_hash = _hash_key(api_key)

    # Use compare_digest to prevent timing attacks
    matched = None
    for stored_hash, data in _api_keys.items():
        if hmac.compare_digest(stored_hash, key_hash):
            matched = data
            break

    if not matched:
        raise HTTPException(status_code=401, detail="Invalid API key.")

    return matched


def get_api_key_from_request(request: Request) -> str | None:
    """Extract API key from Authorization header or query param."""
    # Check header: Authorization: Bearer bb_free_xxx
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    # Check query param: ?api_key=bb_free_xxx
    return request.query_params.get("api_key")


def require_api_key(request: Request) -> dict:
    """
    Dependency — require valid API key for protected endpoints.
    Usage: key_data = require_api_key(request)
    """
    key = get_api_key_from_request(request)
    if not key:
        raise HTTPException(
            status_code=401,
            detail="API key required. Pass as: Authorization: Bearer <key> or ?api_key=<key>",
        )
    return validate_api_key(key)


def is_admin(request: Request) -> bool:
    """Check if request has admin key."""
    key = get_api_key_from_request(request)
    if not key:
        return False
    return hmac.compare_digest(key, _ADMIN_KEY)


def require_admin(request: Request):
    """Dependency — require admin key."""
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Admin access required.")
