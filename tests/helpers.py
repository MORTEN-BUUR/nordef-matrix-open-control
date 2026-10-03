from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nordef_open_control import ActionRequest, MandateClaims
from nordef_open_control.license import LicenseClaims, sign_license, verify_license
from nordef_open_control.root_gate import sign_mandate
from nordef_open_control.service import NordefService


def make_license(vendor: Ed25519PrivateKey, **overrides) -> str:
    now = datetime.now(timezone.utc)
    values = dict(
        license_id="lic-test", licensee="Test AS", key_id="vendor-1", scopes=("*",),
        max_agents=3, max_requests=0, issued_at=(now - timedelta(minutes=1)).isoformat(),
        expires_at=(now + timedelta(days=30)).isoformat(),
    )
    values.update(overrides)
    return sign_license(vendor, LicenseClaims(**values))


def make_mandate(root: Ed25519PrivateKey, request: ActionRequest, **overrides) -> str:
    now = datetime.now(timezone.utc)
    values = dict(
        subject="ops-lead", action=request.action, target=request.target, scope=request.scope,
        side_effects=request.side_effects, issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(), nonce=secrets.token_urlsafe(16),
        request_hash=request.request_hash(), key_id="root-1", test_only=False,
    )
    values.update(overrides)
    return sign_mandate(root, MandateClaims(**values))


def make_service(state_root, *, tenant="acme", agent_id="agent-1", license_overrides=None,
                 trusted_sources=(), root_key=None, vendor_key=None) -> NordefService:
    vendor_key = vendor_key or Ed25519PrivateKey.generate()
    token = make_license(vendor_key, **(license_overrides or {}))
    claims = verify_license(token, {"vendor-1": vendor_key.public_key()})
    keys = {"root-1": root_key.public_key()} if root_key else {}
    return NordefService(
        state_root=state_root, tenant=tenant, agent_id=agent_id, license_claims=claims,
        mandate_keys=keys, trusted_sources=trusted_sources,
    )
