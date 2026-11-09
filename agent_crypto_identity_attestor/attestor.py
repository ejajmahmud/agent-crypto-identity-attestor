"""Core Crypto Identity Attestor implementation."""
import time
import hmac
import hashlib
import json
import base64
from typing import Dict, List, Set, Optional, Any


class AgentIdentity:
    def __init__(self, agent_id: str, secret_key: str, allowed_roles: List[str]):
        self.agent_id = agent_id
        self.secret_key = secret_key
        self.allowed_roles = set(allowed_roles)


class DelegationToken:
    def __init__(self, token_str: str, payload: Dict[str, Any], is_valid: bool, error: str = ""):
        self.token_str = token_str
        self.payload = payload
        self.is_valid = is_valid
        self.error = error


class CryptoIdentityAttestor:
    def __init__(self, master_secret: str):
        self.master_secret = master_secret
        self.revoked_tokens: Set[str] = set()
        self.used_nonces: Set[str] = set()

    def issue_token(self, agent_id: str, roles: List[str], ttl_seconds: int = 300) -> str:
        now = time.time()
        nonce = hashlib.sha256(f"{agent_id}:{now}".encode()).hexdigest()[:12]
        payload = {
            "sub": agent_id,
            "roles": roles,
            "iat": now,
            "exp": now + ttl_seconds,
            "nonce": nonce
        }
        raw_json = json.dumps(payload, separators=(',', ':'), sort_keys=True)
        encoded_payload = base64.urlsafe_b64encode(raw_json.encode()).decode().rstrip("=")
        sig = hmac.new(self.master_secret.encode(), encoded_payload.encode(), hashlib.sha256).hexdigest()[:32]
        return f"{encoded_payload}.{sig}"

    def verify_token(self, token_str: str, required_role: Optional[str] = None) -> DelegationToken:
        parts = token_str.split(".")
        if len(parts) != 2:
            return DelegationToken(token_str, {}, False, "Malformed token format")

        encoded_payload, sig = parts
        expected_sig = hmac.new(self.master_secret.encode(), encoded_payload.encode(), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(sig, expected_sig):
            return DelegationToken(token_str, {}, False, "Invalid cryptographic signature")

        try:
            # Add padding back if necessary
            padding = 4 - (len(encoded_payload) % 4)
            if padding and padding != 4:
                encoded_payload += "=" * padding
            raw_json = base64.urlsafe_b64decode(encoded_payload.encode()).decode()
            payload = json.loads(raw_json)
        except Exception as e:
            return DelegationToken(token_str, {}, False, f"Payload decode failure: {e}")

        # Check expiration
        now = time.time()
        if payload.get("exp", 0) < now:
            return DelegationToken(token_str, payload, False, "Token expired")

        nonce = payload.get("nonce", "")
        if nonce in self.revoked_tokens:
            return DelegationToken(token_str, payload, False, "Token has been revoked")

        if required_role and required_role not in payload.get("roles", []):
            return DelegationToken(token_str, payload, False, f"Missing required role: {required_role}")

        return DelegationToken(token_str, payload, True)

    def revoke_token(self, token_str: str):
        parts = token_str.split(".")
        if len(parts) == 2:
            try:
                padding = 4 - (len(parts[0]) % 4)
                if padding and padding != 4:
                    parts[0] += "=" * padding
                raw_json = base64.urlsafe_b64decode(parts[0].encode()).decode()
                payload = json.loads(raw_json)
                nonce = payload.get("nonce")
                if nonce:
                    self.revoked_tokens.add(nonce)
            except Exception:
                pass
