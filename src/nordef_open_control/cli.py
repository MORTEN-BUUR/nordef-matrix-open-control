"""Command-line entry points.

nordef-mcp    the MCP server (runs next to the agent; holds public keys only)
nordef-root   human signer tools (runs on the approver's own machine; holds private keys)
nordef-admin  operator tools on the server (stop button, verification, audit report)
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .compliance import build_report, render_markdown
from .control import ControlPlane
from .license import LicenseClaims, LicenseError, sign_license, verify_license
from .models import ActionRequest, InputEnvelope, MandateClaims
from .root_gate import sign_mandate
from .sandbox import SandboxError, check_runtime
from .tenancy import HaltSwitch, TenantPaths, validate_tenant

# ---- key helpers ------------------------------------------------------------


def _passphrase() -> bytes | None:
    value = os.environ.get("NORDEF_KEY_PASSPHRASE")
    return value.encode("utf-8") if value else None


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=_passphrase())
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("not an Ed25519 private key")
    return key


def public_key_b64(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def load_public_keys(path: str | Path | None) -> dict[str, Ed25519PublicKey]:
    """Read ``{"keys": {"<key_id>": "<base64 raw Ed25519 public key>"}}``."""
    if not path:
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {
        key_id: Ed25519PublicKey.from_public_bytes(base64.b64decode(value, validate=True))
        for key_id, value in (data.get("keys") or {}).items()
    }


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


# ---- nordef-mcp -------------------------------------------------------------


def _dev_license() -> tuple[str, dict[str, Ed25519PublicKey]]:
    key = Ed25519PrivateKey.generate()
    now = _now()
    claims = LicenseClaims(
        license_id=f"dev-{uuid.uuid4().hex[:12]}", licensee="LAB-DEV (not for production)",
        key_id="dev-vendor", scopes=("*",), max_agents=5, max_requests=10_000,
        issued_at=now.isoformat(), expires_at=(now + timedelta(days=1)).isoformat(), dev=True,
    )
    return sign_license(key, claims), {"dev-vendor": key.public_key()}


def build_service_from_args(args: argparse.Namespace):
    from .service import NordefService

    if args.dev:
        token, vendor_keys = _dev_license()
    else:
        if not args.license or not args.license_keys:
            raise SystemExit("--license and --license-keys are required (or --dev for LAB)")
        token = Path(args.license).read_text(encoding="utf-8").strip()
        vendor_keys = load_public_keys(args.license_keys)
    try:
        claims = verify_license(token, vendor_keys, allow_dev=args.dev)
    except LicenseError as exc:
        raise SystemExit(f"license rejected: {exc.reason}")
    return NordefService(
        state_root=args.state_dir,
        tenant=args.tenant,
        agent_id=args.agent_id,
        license_claims=claims,
        mandate_keys=load_public_keys(args.trusted_keys),
        trusted_sources=[s for s in (args.trusted_source or []) if s],
        policy_pin=args.policy_fingerprint,
        max_ttl_seconds=args.max_ttl,
    )


def mcp_main(argv: list[str] | None = None) -> int:
    env = os.environ.get
    parser = argparse.ArgumentParser(prog="nordef-mcp", description="NORDEF Open Control MCP server (stdio)")
    parser.add_argument("--state-dir", default=env("NORDEF_STATE_DIR", "/var/lib/nordef"))
    parser.add_argument("--tenant", default=env("NORDEF_TENANT", "default"))
    parser.add_argument("--agent-id", default=env("NORDEF_AGENT_ID", "agent-1"))
    parser.add_argument("--trusted-keys", default=env("NORDEF_TRUSTED_KEYS"),
                        help="JSON file with human root public keys")
    parser.add_argument("--license", default=env("NORDEF_LICENSE"), help="file containing NORDEF1 key")
    parser.add_argument("--license-keys", default=env("NORDEF_LICENSE_KEYS"),
                        help="JSON file with vendor license public keys")
    parser.add_argument("--trusted-source", action="append",
                        default=[s for s in (env("NORDEF_TRUSTED_SOURCES") or "").split(",") if s],
                        help="input source names the operator trusts (repeatable)")
    parser.add_argument("--policy-fingerprint", default=env("NORDEF_POLICY_FINGERPRINT"))
    parser.add_argument("--max-ttl", type=int, default=900)
    parser.add_argument("--dev", action="store_true", help="LAB mode: ephemeral dev license")
    parser.add_argument("--allow-root", action="store_true", help="LAB only: permit running as root")
    args = parser.parse_args(argv)

    try:
        validate_tenant(args.tenant)
        check_runtime(args.state_dir, allow_root=args.allow_root)
    except (SandboxError, ValueError) as exc:
        print(f"nordef-mcp: refusing to start: {exc}", file=sys.stderr)
        return 2
    service = build_service_from_args(args)
    if args.dev:
        print("nordef-mcp: LAB dev license active — not for production", file=sys.stderr)
    if not service.gate.public_keys:
        print("nordef-mcp: no trusted human keys loaded — every side effect stays held", file=sys.stderr)
    from .mcp_server import build_server

    build_server(service).run("stdio")
    return 0


# ---- nordef-root ------------------------------------------------------------


def root_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nordef-root", description="Human signer tools")
    sub = parser.add_subparsers(dest="cmd", required=True)

    keygen = sub.add_parser("keygen", help="create an Ed25519 key pair")
    keygen.add_argument("--key-id", required=True)
    keygen.add_argument("--out", required=True, help="private key PEM path")

    mandate = sub.add_parser("sign-mandate", help="approve one exact action")
    mandate.add_argument("--key", required=True)
    mandate.add_argument("--key-id", required=True)
    mandate.add_argument("--subject", required=True, help="name/role of the approving human")
    mandate.add_argument("--action", required=True)
    mandate.add_argument("--target", required=True)
    mandate.add_argument("--scope", required=True)
    mandate.add_argument("--side-effects", action="store_true")
    mandate.add_argument("--ttl", type=int, default=300)

    lic = sub.add_parser("issue-license", help="vendor: issue a customer license")
    lic.add_argument("--key", required=True)
    lic.add_argument("--key-id", required=True)
    lic.add_argument("--licensee", required=True)
    lic.add_argument("--scopes", default="*", help="comma-separated tool names or *")
    lic.add_argument("--max-agents", type=int, default=5)
    lic.add_argument("--max-requests", type=int, default=0, help="per month, 0 = unlimited")
    lic.add_argument("--days", type=int, default=365)

    args = parser.parse_args(argv)
    if args.cmd == "keygen":
        key = Ed25519PrivateKey.generate()
        encryption = (serialization.BestAvailableEncryption(_passphrase()) if _passphrase()
                      else serialization.NoEncryption())
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)
        out = Path(args.out)
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(pem)
        public = {"keys": {args.key_id: public_key_b64(key.public_key())}}
        out.with_suffix(".pub.json").write_text(json.dumps(public, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(public, indent=2))
        return 0
    if args.cmd == "sign-mandate":
        key = load_private_key(args.key)
        request = ActionRequest(args.action, args.target, args.scope, args.side_effects)
        now = _now()
        claims = MandateClaims(
            subject=args.subject, action=args.action, target=args.target, scope=args.scope,
            side_effects=args.side_effects, issued_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=args.ttl)).isoformat(),
            nonce=secrets.token_urlsafe(24), request_hash=request.request_hash(),
            key_id=args.key_id, test_only=False,
        )
        print(sign_mandate(key, claims))
        return 0
    key = load_private_key(args.key)
    now = _now()
    claims = LicenseClaims(
        license_id=f"lic-{uuid.uuid4().hex[:16]}", licensee=args.licensee, key_id=args.key_id,
        scopes=tuple(s.strip() for s in args.scopes.split(",") if s.strip()),
        max_agents=args.max_agents, max_requests=args.max_requests,
        issued_at=now.isoformat(), expires_at=(now + timedelta(days=args.days)).isoformat(),
    )
    print(sign_license(key, claims))
    return 0


# ---- nordef-admin -----------------------------------------------------------


def _record_operator_event(paths: TenantPaths, *, category: str, state: str, operator: str,
                           reason: str) -> None:
    control = ControlPlane(paths.dir, context={"tenant": paths.tenant})
    control.record_event(
        envelope=InputEnvelope(source="operator", text=reason or category, trusted=True),
        request=ActionRequest(action=category, target=paths.tenant, scope="control:halt"),
        code=2 if category == "human_halt" else 0, state=state, reason=category,
        extra_metadata={"operator": operator},
    )


def _tenants(root: Path) -> list[str]:
    base = root / "tenants"
    return sorted(p.name for p in base.iterdir() if p.is_dir()) if base.exists() else []


def admin_main(argv: list[str] | None = None) -> int:
    env = os.environ.get
    parser = argparse.ArgumentParser(prog="nordef-admin", description="Operator tools")
    parser.add_argument("--state-dir", default=env("NORDEF_STATE_DIR", "/var/lib/nordef"))
    sub = parser.add_subparsers(dest="cmd", required=True)

    halt = sub.add_parser("halt", help="STOP BUTTON: block every decision tool")
    halt.add_argument("--tenant", help="omit to stop all tenants")
    halt.add_argument("--operator", required=True)
    halt.add_argument("--reason", required=True)

    resume = sub.add_parser("resume", help="release the stop button")
    resume.add_argument("--tenant")
    resume.add_argument("--operator", required=True)
    resume.add_argument("--reason", default="resumed by operator")

    status = sub.add_parser("status")
    status.add_argument("--tenant", default="default")

    verify = sub.add_parser("verify", help="fully verify evidence chains")
    verify.add_argument("--tenant")

    report = sub.add_parser("report", help="audit report for a tenant")
    report.add_argument("--tenant", default="default")
    report.add_argument("--format", choices=["md", "json"], default="md")

    sub.add_parser("fingerprint", help="print the policy fingerprint to pin in config")

    args = parser.parse_args(argv)
    root = Path(args.state_dir)

    if args.cmd == "fingerprint":
        from .integrity import policy_fingerprint
        print(policy_fingerprint())
        return 0

    if args.cmd in {"halt", "resume"}:
        tenants = [validate_tenant(args.tenant)] if args.tenant else _tenants(root)
        target = TenantPaths.create(root, args.tenant).dir if args.tenant else root
        if args.cmd == "halt":
            HaltSwitch.engage(target, operator=args.operator, reason=args.reason)
            for tenant in tenants:
                _record_operator_event(TenantPaths.create(root, tenant), category="human_halt",
                                       state="halt_engaged", operator=args.operator, reason=args.reason)
            print(f"HALT engaged ({'tenant ' + args.tenant if args.tenant else 'all tenants'})")
        else:
            released = HaltSwitch.release(target)
            for tenant in tenants:
                _record_operator_event(TenantPaths.create(root, tenant), category="human_resume",
                                       state="halt_released", operator=args.operator, reason=args.reason)
            print("resumed" if released else "no halt was active at that level")
        return 0

    if args.cmd == "status":
        paths = TenantPaths.create(root, args.tenant)
        print(json.dumps({"tenant": args.tenant, "halt": HaltSwitch(paths).status()}, indent=2))
        return 0

    if args.cmd == "verify":
        tenants = [validate_tenant(args.tenant)] if args.tenant else _tenants(root)
        ok = True
        for tenant in tenants:
            result = ControlPlane(TenantPaths.create(root, tenant).dir).evidence.verify()
            ok &= result.valid
            print(json.dumps({"tenant": tenant, "valid": result.valid, "reason": result.reason,
                              "records": result.records}))
        return 0 if ok else 1

    paths = TenantPaths.create(root, args.tenant)
    data = build_report(ControlPlane(paths.dir).evidence, tenant=args.tenant,
                        halt_status=HaltSwitch(paths).status())
    print(render_markdown(data) if args.format == "md" else json.dumps(data, indent=2, ensure_ascii=False))
    return 0 if data["chain"]["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(mcp_main())
