"""
Day 27 Lab 2
Trusted Logging & Forensic Baseline

Purpose:
Build a trusted forensic logging baseline for AI security events.

This lab demonstrates:
- Stable event identifiers
- Session and trace correlation
- Event sequencing
- UTC timestamps
- Event provenance
- Security-relevant metadata
- SHA-256 event integrity
- Chain-linked forensic events
- Evidence completeness
- Timeline reconstruction readiness

Core Principle:
If an AI security event cannot be observed and reconstructed,
it cannot be reliably investigated or improved.
"""

import json
import hashlib
from datetime import datetime, timezone
from collections import Counter


# ============================================================
# CONFIGURATION
# ============================================================

SYSTEM = {
    "application": "synthetic-ai-workflow",
    "environment": "day27-lab",
    "system_version": "v1.0.0",
    "model_version": "synthetic-llm-v1",
    "prompt_version": "prompt-v1",
    "policy_version": "policy-v1",
    "guardrail_version": "guardrail-v1",
}

SESSION = {
    "session_id": "SESSION-2702",
    "trace_id": "TRACE-2702",
    "user_id": "USER-2701",
    "agent_id": "AGENT-2701",
}

ASSETS = {
    "trusted_record": "R-2702",
    "trusted_tool": "read_record",
    "rag_store": "RAG-2701",
    "memory_store": "MEMORY-2701",
}


# ============================================================
# FORENSIC EVENT STORE
# ============================================================

FORENSIC_LOG = []


# ============================================================
# HELPERS
# ============================================================

def utc_timestamp():
    return datetime.now(timezone.utc).isoformat()


def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    )


def sha256_value(value):
    return hashlib.sha256(
        canonical_json(value).encode("utf-8")
    ).hexdigest()


def print_json(value):
    print(json.dumps(value, indent=2))


# ============================================================
# FORENSIC LOGGER
# ============================================================

def log_forensic_event(
    event_type,
    component,
    action,
    status,
    details,
    severity="info",
):

    sequence = len(FORENSIC_LOG) + 1

    event_id = f"FORENSIC-EVT-{sequence:04d}"

    previous_hash = (
        FORENSIC_LOG[-1]["event_hash"]
        if FORENSIC_LOG
        else "GENESIS"
    )

    event = {
        "event_id": event_id,
        "sequence": sequence,
        "timestamp": utc_timestamp(),

        "session_id": SESSION["session_id"],
        "trace_id": SESSION["trace_id"],
        "user_id": SESSION["user_id"],
        "agent_id": SESSION["agent_id"],

        "event_type": event_type,
        "component": component,
        "action": action,
        "status": status,
        "severity": severity,

        "system_version": SYSTEM["system_version"],
        "model_version": SYSTEM["model_version"],
        "prompt_version": SYSTEM["prompt_version"],
        "policy_version": SYSTEM["policy_version"],
        "guardrail_version": SYSTEM["guardrail_version"],

        "provenance": {
            "application": SYSTEM["application"],
            "environment": SYSTEM["environment"],
            "logger": "trusted-forensic-logger",
        },

        "details": details,

        "previous_event_hash": previous_hash,
    }

    event_hash = sha256_value(event)

    event["event_hash"] = event_hash

    FORENSIC_LOG.append(event)

    return event


# ============================================================
# TRUSTED AI WORKFLOW
# ============================================================

def execute_trusted_workflow():

    log_forensic_event(
        event_type="prompt_received",
        component="input_gateway",
        action="receive_prompt",
        status="success",
        details={
            "prompt": "Read authorized record R-2702.",
            "source": "authenticated_user",
        },
    )

    log_forensic_event(
        event_type="prompt_classified",
        component="security_classifier",
        action="classify_prompt",
        status="success",
        details={
            "classification": "benign",
            "suspicious": False,
        },
    )

    log_forensic_event(
        event_type="rag_retrieval",
        component="retrieval_service",
        action="retrieve_context",
        status="success",
        details={
            "rag_store": ASSETS["rag_store"],
            "document_ids": ["DOC-2701"],
            "trusted": True,
        },
    )

    log_forensic_event(
        event_type="memory_read",
        component="memory_service",
        action="read_memory",
        status="success",
        details={
            "memory_store": ASSETS["memory_store"],
            "records_read": 1,
        },
    )

    log_forensic_event(
        event_type="agent_plan",
        component="agent_planner",
        action="generate_plan",
        status="success",
        details={
            "tool": ASSETS["trusted_tool"],
            "target": ASSETS["trusted_record"],
            "privileged": False,
        },
    )

    log_forensic_event(
        event_type="authorization_check",
        component="authorization_service",
        action="authorize_execution",
        status="success",
        details={
            "tool": ASSETS["trusted_tool"],
            "target": ASSETS["trusted_record"],
            "authorized": True,
        },
    )

    log_forensic_event(
        event_type="tool_execution",
        component="record_service",
        action="read_record",
        status="success",
        details={
            "target": ASSETS["trusted_record"],
            "authorized": True,
            "unauthorized_impact": False,
        },
    )

    log_forensic_event(
        event_type="response_generated",
        component="llm_runtime",
        action="generate_response",
        status="success",
        details={
            "sensitive_data_disclosed": False,
            "response_status": "completed",
        },
    )


# ============================================================
# EVENT INTEGRITY VALIDATION
# ============================================================

def verify_event_hash(event):

    stored_hash = event["event_hash"]

    event_copy = dict(event)

    del event_copy["event_hash"]

    calculated_hash = sha256_value(event_copy)

    return stored_hash == calculated_hash


# ============================================================
# HASH-CHAIN VALIDATION
# ============================================================

def verify_hash_chain():

    for index, event in enumerate(FORENSIC_LOG):

        if index == 0:
            expected_previous = "GENESIS"

        else:
            expected_previous = (
                FORENSIC_LOG[index - 1]["event_hash"]
            )

        if event["previous_event_hash"] != expected_previous:
            return False

    return True


# ============================================================
# SEQUENCE VALIDATION
# ============================================================

def verify_sequence():

    expected = list(
        range(1, len(FORENSIC_LOG) + 1)
    )

    actual = [
        event["sequence"]
        for event in FORENSIC_LOG
    ]

    return actual == expected


# ============================================================
# CORRELATION VALIDATION
# ============================================================

def verify_correlation():

    session_ids = {
        event["session_id"]
        for event in FORENSIC_LOG
    }

    trace_ids = {
        event["trace_id"]
        for event in FORENSIC_LOG
    }

    return {
        "unique_session_ids": len(session_ids),
        "unique_trace_ids": len(trace_ids),

        "session_correlation_valid":
            len(session_ids) == 1,

        "trace_correlation_valid":
            len(trace_ids) == 1,
    }


# ============================================================
# FORENSIC COMPLETENESS
# ============================================================

def verify_completeness():

    required_fields = {
        "event_id",
        "sequence",
        "timestamp",
        "session_id",
        "trace_id",
        "user_id",
        "agent_id",
        "event_type",
        "component",
        "action",
        "status",
        "severity",
        "system_version",
        "model_version",
        "prompt_version",
        "policy_version",
        "guardrail_version",
        "provenance",
        "details",
        "previous_event_hash",
        "event_hash",
    }

    complete = 0

    for event in FORENSIC_LOG:

        if required_fields.issubset(event.keys()):
            complete += 1

    rate = (
        complete / len(FORENSIC_LOG) * 100
        if FORENSIC_LOG
        else 0.0
    )

    return {
        "total_events": len(FORENSIC_LOG),
        "complete_events": complete,
        "forensic_completeness_rate": rate,
    }


# ============================================================
# TIMELINE RECONSTRUCTION
# ============================================================

def reconstruct_timeline():

    timeline = []

    for event in sorted(
        FORENSIC_LOG,
        key=lambda item: item["sequence"],
    ):

        timeline.append({
            "sequence": event["sequence"],
            "timestamp": event["timestamp"],
            "event_id": event["event_id"],
            "component": event["component"],
            "action": event["action"],
            "status": event["status"],
        })

    return timeline


# ============================================================
# EVENT TYPE DISTRIBUTION
# ============================================================

def event_distribution():

    return Counter(
        event["event_type"]
        for event in FORENSIC_LOG
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "\n=== Day 27 Lab 2: "
        "Trusted Logging & Forensic Baseline ==="
    )

    print(
        "\n"
        + "=" * 72
    )

    print(
        "        TRUSTED FORENSIC LOGGING CONFIGURATION"
    )

    print(
        "=" * 72
    )

    print_json(SYSTEM)
    print_json(SESSION)

    execute_trusted_workflow()

    print(
        "\n"
        + "=" * 72
    )

    print(
        "        FORENSIC EVENT LOG"
    )

    print(
        "=" * 72
    )

    for event in FORENSIC_LOG:

        print(
            f"\n{event['event_id']} | "
            f"SEQ={event['sequence']} | "
            f"{event['event_type']} | "
            f"{event['component']}"
        )

        print(
            f"Hash: "
            f"{event['event_hash']}"
        )

        print(
            f"Previous Hash: "
            f"{event['previous_event_hash']}"
        )

        print_json(
            event["details"]
        )

    # ========================================================
    # EVENT INTEGRITY
    # ========================================================

    integrity_results = [
        verify_event_hash(event)
        for event in FORENSIC_LOG
    ]

    valid_integrity_count = sum(
        integrity_results
    )

    integrity_rate = (
        valid_integrity_count
        / len(FORENSIC_LOG)
        * 100
        if FORENSIC_LOG
        else 0.0
    )

    # ========================================================
    # OTHER VALIDATIONS
    # ========================================================

    chain_valid = verify_hash_chain()

    sequence_valid = verify_sequence()

    correlation = verify_correlation()

    completeness = verify_completeness()

    timeline = reconstruct_timeline()

    # ========================================================
    # SUMMARY
    # ========================================================

    print(
        "\n"
        + "=" * 72
    )

    print(
        "        FORENSIC EVIDENCE VALIDATION"
    )

    print(
        "=" * 72
    )

    print(
        "Total Events:",
        completeness["total_events"]
    )

    print(
        "Complete Events:",
        completeness["complete_events"]
    )

    print(
        "Forensic Completeness Rate:",
        f"{completeness['forensic_completeness_rate']:.2f}%"
    )

    print(
        "Events With Valid Integrity:",
        valid_integrity_count
    )

    print(
        "Event Integrity Validation Rate:",
        f"{integrity_rate:.2f}%"
    )

    print(
        "Hash Chain Valid:",
        chain_valid
    )

    print(
        "Sequence Valid:",
        sequence_valid
    )

    print(
        "Session Correlation Valid:",
        correlation[
            "session_correlation_valid"
        ]
    )

    print(
        "Trace Correlation Valid:",
        correlation[
            "trace_correlation_valid"
        ]
    )

    # ========================================================
    # TIMELINE
    # ========================================================

    print(
        "\n"
        + "=" * 72
    )

    print(
        "        RECONSTRUCTED FORENSIC TIMELINE"
    )

    print(
        "=" * 72
    )

    for entry in timeline:

        print(
            f"{entry['sequence']:02d} | "
            f"{entry['timestamp']} | "
            f"{entry['event_id']} | "
            f"{entry['component']} | "
            f"{entry['action']} | "
            f"{entry['status']}"
        )

    # ========================================================
    # DISTRIBUTION
    # ========================================================

    print(
        "\n"
        + "=" * 72
    )

    print(
        "        FORENSIC EVENT DISTRIBUTION"
    )

    print(
        "=" * 72
    )

    for event_type, count in sorted(
        event_distribution().items()
    ):

        print(
            f"{event_type}: {count}"
        )

    # ========================================================
    # FORENSIC READINESS
    # ========================================================

    forensic_ready = all([
        completeness[
            "forensic_completeness_rate"
        ] == 100.0,

        integrity_rate == 100.0,

        chain_valid,

        sequence_valid,

        correlation[
            "session_correlation_valid"
        ],

        correlation[
            "trace_correlation_valid"
        ],
    ])

    print(
        "\n"
        + "=" * 72
    )

    print(
        "        FORENSIC READINESS CHECKS"
    )

    print(
        "=" * 72
    )

    print(
        "Complete Evidence Records:",
        completeness[
            "forensic_completeness_rate"
        ] == 100.0
    )

    print(
        "Event Integrity Verified:",
        integrity_rate == 100.0
    )

    print(
        "Hash-Linked Evidence Chain:",
        chain_valid
    )

    print(
        "Event Ordering Verified:",
        sequence_valid
    )

    print(
        "Session Correlation Available:",
        correlation[
            "session_correlation_valid"
        ]
    )

    print(
        "Trace Correlation Available:",
        correlation[
            "trace_correlation_valid"
        ]
    )

    print(
        "Timeline Reconstruction Possible:",
        len(timeline)
        == len(FORENSIC_LOG)
    )

    print(
        "Trusted Forensic Baseline Valid:",
        forensic_ready
    )

    print(
        "\nSecurity Interpretation:"
    )

    print(
        "The trusted forensic baseline records AI security "
        "events with stable identifiers, UTC timestamps, "
        "session and trace correlation, component provenance, "
        "system-version metadata, event sequencing, and "
        "cryptographic integrity hashes."
    )

    print(
        "Hash-linking the events provides evidence of ordering "
        "and makes later modification or removal detectable "
        "within the synthetic evidence chain."
    )

    print(
        "This does not by itself create production-grade "
        "legal chain-of-custody guarantees, but it establishes "
        "the evidence-quality properties needed for the later "
        "Day 27 forensic exercises."
    )

    print(
        "\nCore Principle:"
    )

    print(
        "If an AI security event cannot be observed and "
        "reconstructed, it cannot be reliably investigated "
        "or improved."
    )


if __name__ == "__main__":
    main()