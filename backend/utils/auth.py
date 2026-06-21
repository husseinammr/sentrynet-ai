"""Auth utilities — JWT token creation and verification."""
import time
import hmac
import hashlib
import base64
import json


SECRET = "sentrynet-secret-key-2025"


def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * pad)


def create_token(payload: dict) -> str:
    header = _b64_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload["exp"] = int(time.time()) + 86400  # 24h
    body = _b64_encode(json.dumps(payload).encode())
    sig_input = f"{header}.{body}".encode()
    sig = hmac.new(SECRET.encode(), sig_input, hashlib.sha256).digest()
    return f"{header}.{body}.{_b64_encode(sig)}"


def verify_token(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        header, body, sig = parts
        sig_input = f"{header}.{body}".encode()
        expected = hmac.new(SECRET.encode(), sig_input, hashlib.sha256).digest()
        if not hmac.compare_digest(_b64_encode(expected), sig):
            return {}
        payload = json.loads(_b64_decode(body))
        if payload.get("exp", 0) < time.time():
            return {}
        return payload
    except Exception:
        return {}
