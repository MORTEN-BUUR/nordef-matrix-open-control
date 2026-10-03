from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from .evidence import EvidenceChain

RETENTION_DAYS_MIN = 183  # EU AI Act art. 26(6): logs kept at least six months

ARTICLE_MAP = [
    {
        "article": "14(4)(a-b)",
        "requirement": "Human can monitor operation and understand capabilities and limits",
        "control": "policy_list / compliance_status tools, evidence_tail, deterministic 0/1/2 codes",
    },
    {
        "article": "14(4)(d)",
        "requirement": "Human can decide not to use, disregard, override or reverse output",
        "control": "side effects held (code 1) until an Ed25519 mandate signed outside the model",
    },
    {
        "article": "14(4)(e)",
        "requirement": "Human can intervene or interrupt through a stop button",
        "control": "nordef-admin halt: every decision tool returns code 2 until a human resumes",
    },
    {
        "article": "26(2)",
        "requirement": "Oversight assigned to competent people with authority",
        "control": "mandate subject + key_id recorded per authorization; keys held by named people",
    },
    {
        "article": "26(5)",
        "requirement": "Monitor operation and report serious incidents",
        "control": "blocked/halt events in evidence chain; report lists counts and halt history",
    },
    {
        "article": "26(6)",
        "requirement": "Keep automatically generated logs at least six months",
        "control": "append-only hash chain, never pruned by the software; retention checked here",
    },
]


def _ts(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    except Exception:
        return None


def build_report(
    chain: EvidenceChain,
    *,
    tenant: str,
    halt_status: dict | None = None,
    license_info: dict | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Summarize the evidence chain for an auditor. Contains hashes and counts, no raw input."""
    verification = chain.verify()
    records = chain._records() if verification.valid else []
    states = Counter(r.get("decision") for r in records)
    codes = Counter(str(r.get("code")) for r in records)
    authorizations = [r for r in records if r.get("decision") == "authorized_dry_run"]
    subjects = sorted({r["metadata"].get("subject") for r in authorizations if r["metadata"].get("subject")})
    halts = [
        {"decision": r["decision"], "timestamp": r["timestamp"], "operator": r["metadata"].get("operator")}
        for r in records if r.get("category") in {"human_halt", "human_resume"}
    ]
    first = _ts(records[0]["timestamp"]) if records else None
    last = _ts(records[-1]["timestamp"]) if records else None
    current = now or datetime.now(timezone.utc)
    span_days = (current - first).days if first else 0
    return {
        "tenant": tenant,
        "generated_at": current.isoformat(),
        "chain": {
            "valid": verification.valid,
            "reason": verification.reason,
            "records": verification.records,
            "head_hash": records[-1]["record_hash"] if records else None,
        },
        "period": {
            "first_record": first.isoformat() if first else None,
            "last_record": last.isoformat() if last else None,
            "days_of_history": span_days,
            "retention_minimum_days": RETENTION_DAYS_MIN,
            "retention_minimum_reached": span_days >= RETENTION_DAYS_MIN,
        },
        "decisions": {"by_code": dict(codes), "by_state": dict(states)},
        "human_oversight": {
            "authorized_actions": len(authorizations),
            "authorizing_subjects": subjects,
            "actions_executed_by_control_plane": sum(bool(r.get("action_taken")) for r in records),
            "halt_active": halt_status is not None,
            "halt_status": halt_status,
            "halt_history": halts,
        },
        "license": license_info,
        "article_map": ARTICLE_MAP,
        "disclaimer": (
            "Technical evidence summary only. Not a legal conclusion; whether a system is "
            "high-risk and which obligations apply must be assessed by qualified counsel."
        ),
    }


def render_markdown(report: dict[str, Any]) -> str:
    chain, period, oversight = report["chain"], report["period"], report["human_oversight"]
    lines = [
        f"# NORDEF evidence report — tenant `{report['tenant']}`",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "## Evidence chain",
        f"- Valid: **{chain['valid']}** ({chain['reason']}), records: {chain['records']}",
        f"- Head hash: `{chain['head_hash']}`",
        f"- History: {period['first_record']} → {period['last_record']} "
        f"({period['days_of_history']} days; ≥{period['retention_minimum_days']} reached: "
        f"{period['retention_minimum_reached']})",
        "",
        "## Decisions",
        *[f"- code {k}: {v}" for k, v in sorted(report["decisions"]["by_code"].items())],
        *[f"- {k}: {v}" for k, v in sorted(report["decisions"]["by_state"].items())],
        "",
        "## Human oversight",
        f"- Human-authorized actions: {oversight['authorized_actions']}",
        f"- Authorizing subjects: {', '.join(oversight['authorizing_subjects']) or '—'}",
        f"- Actions executed by the control plane: {oversight['actions_executed_by_control_plane']}",
        f"- Stop button active now: {oversight['halt_active']}",
        f"- Halt/resume events: {len(oversight['halt_history'])}",
        "",
        "## EU AI Act mapping (technical support, not legal advice)",
        "| Article | Requirement | Control |",
        "|---|---|---|",
        *[f"| {a['article']} | {a['requirement']} | {a['control']} |" for a in report["article_map"]],
        "",
        f"_{report['disclaimer']}_",
        "",
    ]
    return "\n".join(lines)
