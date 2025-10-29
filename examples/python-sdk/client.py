import base64
import hashlib
import hmac
import json
import os
import pathlib
import secrets
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import requests
import sys


@dataclass
class KeySummary:
    id: str
    algorithm: str
    version: int
    state: str
    usage: List[str]
    policy_tags: List[str]


@dataclass
class Approval:
    id: str
    action: str
    subject: str
    requester: str
    approved_by: Optional[str]
    approved_at: Optional[str]
    created_at: str


class FerroHsmClient:
    def __init__(self, endpoint: str, cert: pathlib.Path, key: pathlib.Path, ca_bundle: pathlib.Path, token: str):
        self.endpoint = endpoint.rstrip('/')
        self.session = requests.Session()
        self.session.cert = (str(cert), str(key))
        self.session.verify = str(ca_bundle)
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
        })

    def create_key(self, algorithm: str, usage: List[str], tags: List[str]) -> KeySummary:
        payload = {
            "algorithm": algorithm,
            "usage": usage,
            "policy_tags": tags,
        }
        response = self.session.post(f"{self.endpoint}/api/v1/keys", json=payload, timeout=10)
        if response.status_code == 202:
            message = response.json().get("error", "dual-control approval required")
            raise RuntimeError(f"key creation pending approval: {message}")
        response.raise_for_status()
        return KeySummary(**response.json())

    def sign(self, key_id: str, payload: bytes) -> bytes:
        body = {"payload_b64": base64.b64encode(payload).decode()}
        response = self.session.post(
            f"{self.endpoint}/api/v1/keys/{key_id}/sign",
            json=body,
            timeout=10,
        )
        if response.status_code == 202:
            message = response.json().get("error", "dual-control approval required")
            raise RuntimeError(f"signature pending approval: {message}")
        response.raise_for_status()
        data = response.json()
        return base64.b64decode(data["signature_b64"])

    def list_approvals(self) -> List[Approval]:
        response = self.session.get(f"{self.endpoint}/api/v1/approvals", timeout=10)
        if response.status_code == 403:
            raise RuntimeError("approvals listing requires operator or auditor role")
        response.raise_for_status()
        return [Approval(**item) for item in response.json()]

    def deny_approval(self, approval_id: str) -> None:
        response = self.session.post(
            f"{self.endpoint}/api/v1/approvals/{approval_id}/deny",
            timeout=10,
        )
        if response.status_code == 404:
            raise RuntimeError(f"approval {approval_id} not found")
        response.raise_for_status()

    def metrics_snapshot(self) -> Dict[str, int]:
        response = self.session.get(f"{self.endpoint}/metrics", timeout=10)
        response.raise_for_status()
        body = response.text
        return {
            "rate_allowed": parse_counter(body, "ferrohsm_rate_limit_allowed_total"),
            "rate_blocked": parse_counter(body, "ferrohsm_rate_limit_blocked_total"),
            "cache_hits": parse_counter(body, "ferrohsm_key_cache_hit_total"),
            "cache_misses": parse_counter(body, "ferrohsm_key_cache_miss_total"),
            "cache_stores": parse_counter(body, "ferrohsm_key_cache_store_total"),
        }


if __name__ == "__main__":
    try:
        token = resolve_token()
        client = FerroHsmClient(
            endpoint="https://localhost:8443",
            cert=pathlib.Path("client.pem"),
            key=pathlib.Path("client.key.pem"),
            ca_bundle=pathlib.Path("ca.pem"),
            token=token,
        )
        # Create a standard AES key
        aes_key = client.create_key("Aes256Gcm", ["Encrypt", "Decrypt"], ["dev"])
        print(f"Created AES key {aes_key.id} ({aes_key.algorithm})")
        
        # Create a post-quantum ML-KEM key
        try:
            pqc_key = client.create_key(
                "MlKem768",
                ["KeyEncapsulation"],
                ["pqc", "quantum_resistant"],
            )
            print(f"Created PQC key {pqc_key.id} ({pqc_key.algorithm})")
        except Exception as e:
            print(f"PQC key creation failed: {e}")

        # Create a post-quantum ML-DSA signature key
        try:
            sig_key = client.create_key(
                "MlDsa65",
                ["Sign", "Verify"],
                ["pqc", "quantum_resistant"],
            )
            print(f"Created PQC signature key {sig_key.id} ({sig_key.algorithm})")
        except Exception as e:
            print(f"PQC signature key creation failed: {e}")

        # Sign a payload with the AES key
        signature = client.sign(aes_key.id, b"python-signed-payload")
        print("Signature:", base64.b64encode(signature).decode())

        try:
            approvals = client.list_approvals()
        except RuntimeError as exc:
            print(f"Approvals unavailable: {exc}")
        else:
            if approvals:
                print(f"{len(approvals)} approvals pending:")
                for approval in approvals:
                    print(f"- {approval.action} {approval.subject} requested by {approval.requester}")
            else:
                print("No pending approvals")

        metrics = client.metrics_snapshot()
        print(
            "Metrics:",
            "rate_allowed={rate_allowed} rate_blocked={rate_blocked} cache_hits={cache_hits} cache_misses={cache_misses} cache_stores={cache_stores}".format(
                **metrics
            ),
        )
    except RuntimeError as exc:
        print(f"Operation requires approval: {exc}")
        sys.exit(0)


def resolve_token() -> str:
    pre_signed = os.getenv("FERROHSM_AUTH_TOKEN")
    if pre_signed:
        return pre_signed
    secret = os.getenv("FERROHSM_JWT_SECRET")
    if not secret:
        raise RuntimeError("FERROHSM_JWT_SECRET environment variable is required")
    return build_jwt(secret, "python-sdk", ["operator"], ttl_seconds=300)


def build_jwt(secret: str, actor: str, roles: List[str], ttl_seconds: int) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    now = int(time.time())
    payload = {
        "sub": actor,
        "roles": roles,
        "iat": now,
        "exp": now + ttl_seconds,
        "sid": secrets.token_hex(16),
    }
    payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    unsigned = f"{header}.{payload_encoded}"
    key = decode_secret(secret)
    signature = hmac.new(key, unsigned.encode(), hashlib.sha256).digest()
    signature_encoded = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return f"{unsigned}.{signature_encoded}"


def decode_secret(secret: str) -> bytes:
    try:
        return base64.b64decode(secret, validate=True)
    except (base64.binascii.Error, ValueError):
        if not secret.strip():
            raise RuntimeError("JWT secret cannot be empty")
        return secret.encode()


def parse_counter(metrics: str, name: str) -> int:
    for line in metrics.splitlines():
        if line.startswith(name):
            parts = line.split()
            if len(parts) == 2:
                try:
                    return int(float(parts[1]))
                except ValueError:
                    return 0
    return 0
