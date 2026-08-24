"""
Day 27 Lab 1
Synthetic AI Security Telemetry Environment

Purpose:
Create a synthetic AI security telemetry environment capable of
recording prompt, RAG, memory, agent, tool, authorization, policy,
security, and response events for later detection, forensic
reconstruction, blast-radius analysis, and incident response.

Core Principle:
If an AI security event cannot be observed and reconstructed,
it cannot be reliably investigated or improved.
"""

import json
from datetime import datetime, timezone
from collections import Counter


# ============================================================
# HELPERS
# ============================================================

def utc_timestamp():
    return datetime.now(
        timezone.utc
    ).isoformat()


def print_json(value):
    print(
        json.dumps(
            value,
            indent=2,
        )
    )


# ============================================================
# SYNTHETIC AI SYSTEM
# ============================================================

SYSTEM = {
    "application": "synthetic-ai-workflow",
    "environment": "day27-lab",
    "version": "v1.0.0",
    "model": "synthetic-llm",
    "agent_id": "AGENT-2701",
    "session_id": "SESSION-2701",
    "user_id": "USER-2701",
}


# ============================================================
# SECURITY ASSETS
# ============================================================

ASSETS = {
    "trusted_record": "R-2702",
    "restricted_record": "R-2799",
    "trusted_tool": "read_record",
    "privileged_tool": "delete_record",
    "trusted_authority": "security_controller",
    "memory_store": "MEMORY-2701",
    "rag_store": "RAG-2701",
}


# ============================================================
# EVENT TYPES
# ============================================================

EVENT_TYPES = {
    "prompt_received",
    "prompt_classified",
    "rag_retrieval",
    "context_loaded",
    "memory_read",
    "memory_write",
    "agent_plan",
    "tool_selected",
    "tool_parameters",
    "authorization_check",
    "tool_execution",
    "policy_decision",
    "security_alert",
    "response_generated",
    "incident_action",
}


# ============================================================
# TELEMETRY STORE
# ============================================================

TELEMETRY = []


# ============================================================
# EVENT LOGGER
# ============================================================

def log_event(
    event_type,
    component,
    action,
    status,
    details=None,
    severity="info",
):

    if event_type not in EVENT_TYPES:
        raise ValueError(
            f"Unsupported event type: {event_type}"
        )

    event = {
        "event_id":
            f"EVT-{len(TELEMETRY) + 1:04d}",

        "timestamp":
            utc_timestamp(),

        "session_id":
            SYSTEM["session_id"],

        "agent_id":
            SYSTEM["agent_id"],

        "user_id":
            SYSTEM["user_id"],

        "event_type":
            event_type,

        "component":
            component,

        "action":
            action,

        "status":
            status,

        "severity":
            severity,

        "details":
            details or {},
    }

    TELEMETRY.append(
        event
    )

    return event


# ============================================================
# TRUSTED WORKFLOW
# ============================================================

def execute_trusted_workflow():

    log_event(
        event_type="prompt_received",
        component="input_gateway",
        action="receive_prompt",
        status="success",
        details={
            "prompt":
                "Read authorized record R-2702.",
            "source":
                "user",
        },
    )

    log_event(
        event_type="prompt_classified",
        component="security_classifier",
        action="classify_prompt",
        status="success",
        details={
            "classification":
                "benign",
            "suspicious":
                False,
        },
    )

    log_event(
        event_type="rag_retrieval",
        component="retrieval_service",
        action="retrieve_context",
        status="success",
        details={
            "rag_store":
                ASSETS["rag_store"],
            "documents":
                ["DOC-2701"],
            "trusted":
                True,
        },
    )

    log_event(
        event_type="context_loaded",
        component="llm_runtime",
        action="load_context",
        status="success",
        details={
            "trusted_target":
                ASSETS["trusted_record"],
            "restricted_target":
                False,
        },
    )

    log_event(
        event_type="memory_read",
        component="memory_service",
        action="read_memory",
        status="success",
        details={
            "memory_store":
                ASSETS["memory_store"],
            "records_read":
                1,
        },
    )

    log_event(
        event_type="agent_plan",
        component="agent_planner",
        action="generate_plan",
        status="success",
        details={
            "proposed_tool":
                ASSETS["trusted_tool"],
            "proposed_target":
                ASSETS["trusted_record"],
            "privileged":
                False,
        },
    )

    log_event(
        event_type="tool_selected",
        component="tool_router",
        action="select_tool",
        status="success",
        details={
            "tool":
                ASSETS["trusted_tool"],
            "allowed":
                True,
        },
    )

    log_event(
        event_type="tool_parameters",
        component="tool_router",
        action="validate_parameters",
        status="success",
        details={
            "target":
                ASSETS["trusted_record"],
            "scope":
                "single_record",
            "validated":
                True,
        },
    )

    log_event(
        event_type="authorization_check",
        component="authorization_service",
        action="authorize_execution",
        status="success",
        details={
            "tool":
                ASSETS["trusted_tool"],
            "target":
                ASSETS["trusted_record"],
            "authorized":
                True,
        },
    )

    log_event(
        event_type="tool_execution",
        component="record_service",
        action="read_record",
        status="success",
        details={
            "target":
                ASSETS["trusted_record"],
            "classification":
                "internal",
            "unauthorized_impact":
                False,
        },
    )

    log_event(
        event_type="response_generated",
        component="llm_runtime",
        action="generate_response",
        status="success",
        details={
            "response":
                "Authorized record successfully reviewed.",
            "sensitive_data_disclosed":
                False,
        },
    )


# ============================================================
# TELEMETRY VALIDATION
# ============================================================

def validate_telemetry():

    required_fields = {
        "event_id",
        "timestamp",
        "session_id",
        "agent_id",
        "user_id",
        "event_type",
        "component",
        "action",
        "status",
        "severity",
        "details",
    }

    complete_events = 0

    for event in TELEMETRY:

        if required_fields.issubset(
            event.keys()
        ):
            complete_events += 1

    return {
        "total_events":
            len(TELEMETRY),

        "complete_events":
            complete_events,

        "telemetry_completeness_rate":
            (
                complete_events
                / len(TELEMETRY)
                * 100
                if TELEMETRY
                else 0.0
            ),

        "unique_components":
            len({
                event["component"]
                for event in TELEMETRY
            }),

        "unique_event_types":
            len({
                event["event_type"]
                for event in TELEMETRY
            }),
    }


# ============================================================
# EVENT DISTRIBUTION
# ============================================================

def event_distribution():

    return dict(
        Counter(
            event["event_type"]
            for event in TELEMETRY
        )
    )


# ============================================================
# SECURITY OBSERVABILITY CHECKS
# ============================================================

def observability_checks():

    required_observability = {
        "prompt_received",
        "prompt_classified",
        "rag_retrieval",
        "context_loaded",
        "memory_read",
        "agent_plan",
        "tool_selected",
        "tool_parameters",
        "authorization_check",
        "tool_execution",
        "response_generated",
    }

    observed = {
        event["event_type"]
        for event in TELEMETRY
    }

    missing = (
        required_observability
        - observed
    )

    return {
        "prompt_observable":
            "prompt_received"
            in observed,

        "rag_observable":
            "rag_retrieval"
            in observed,

        "memory_observable":
            "memory_read"
            in observed,

        "agent_plan_observable":
            "agent_plan"
            in observed,

        "tool_selection_observable":
            "tool_selected"
            in observed,

        "authorization_observable":
            "authorization_check"
            in observed,

        "execution_observable":
            "tool_execution"
            in observed,

        "response_observable":
            "response_generated"
            in observed,

        "missing_required_event_types":
            sorted(
                missing
            ),

        "forensic_reconstruction_possible":
            len(missing) == 0,
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "\n=== Day 27 Lab 1: "
        "Synthetic AI Security Telemetry Environment ==="
    )


    print(
        "\n"
        + "=" * 68
    )

    print(
        "        SYNTHETIC AI SYSTEM"
    )

    print(
        "=" * 68
    )

    print_json(
        SYSTEM
    )


    print(
        "\n"
        + "=" * 68
    )

    print(
        "        SECURITY ASSETS"
    )

    print(
        "=" * 68
    )

    print_json(
        ASSETS
    )


    # ========================================================
    # RUN TRUSTED WORKFLOW
    # ========================================================

    execute_trusted_workflow()


    print(
        "\n"
        + "=" * 68
    )

    print(
        "        GENERATED SECURITY TELEMETRY"
    )

    print(
        "=" * 68
    )


    for event in TELEMETRY:

        print(
            f"\n{event['event_id']} | "
            f"{event['event_type']} | "
            f"{event['component']} | "
            f"{event['status']}"
        )

        print_json(
            event["details"]
        )


    # ========================================================
    # VALIDATION
    # ========================================================

    validation = (
        validate_telemetry()
    )


    print(
        "\n"
        + "=" * 68
    )

    print(
        "        TELEMETRY VALIDATION SUMMARY"
    )

    print(
        "=" * 68
    )


    print(
        "Total Events:",
        validation[
            "total_events"
        ]
    )

    print(
        "Complete Events:",
        validation[
            "complete_events"
        ]
    )

    print(
        "Telemetry Completeness Rate:",
        f"{validation['telemetry_completeness_rate']:.2f}%"
    )

    print(
        "Unique Components:",
        validation[
            "unique_components"
        ]
    )

    print(
        "Unique Event Types:",
        validation[
            "unique_event_types"
        ]
    )


    # ========================================================
    # EVENT DISTRIBUTION
    # ========================================================

    print(
        "\n"
        + "=" * 68
    )

    print(
        "        EVENT TYPE DISTRIBUTION"
    )

    print(
        "=" * 68
    )


    for event_type, count in sorted(
        event_distribution().items()
    ):

        print(
            f"{event_type}: {count}"
        )


    # ========================================================
    # OBSERVABILITY
    # ========================================================

    checks = (
        observability_checks()
    )


    print(
        "\n"
        + "=" * 68
    )

    print(
        "        AI SECURITY OBSERVABILITY CHECKS"
    )

    print(
        "=" * 68
    )


    print(
        "Prompt Observable:",
        checks[
            "prompt_observable"
        ]
    )

    print(
        "RAG Observable:",
        checks[
            "rag_observable"
        ]
    )

    print(
        "Memory Observable:",
        checks[
            "memory_observable"
        ]
    )

    print(
        "Agent Plan Observable:",
        checks[
            "agent_plan_observable"
        ]
    )

    print(
        "Tool Selection Observable:",
        checks[
            "tool_selection_observable"
        ]
    )

    print(
        "Authorization Observable:",
        checks[
            "authorization_observable"
        ]
    )

    print(
        "Execution Observable:",
        checks[
            "execution_observable"
        ]
    )

    print(
        "Response Observable:",
        checks[
            "response_observable"
        ]
    )

    print(
        "Missing Required Event Types:",
        checks[
            "missing_required_event_types"
        ]
    )

    print(
        "Forensic Reconstruction Possible:",
        checks[
            "forensic_reconstruction_possible"
        ]
    )


    print(
        "\nSecurity Interpretation:"
    )

    print(
        "The synthetic telemetry environment records security-relevant "
        "events across prompt ingestion, retrieval, context loading, "
        "memory, agent planning, tool selection, parameter validation, "
        "authorization, execution, and response generation."
    )

    print(
        "This establishes the observability foundation required for "
        "later attack detection, incident timeline reconstruction, "
        "evidence preservation, blast-radius analysis, and response."
    )


    print(
        "\nCore Principle:"
    )

    print(
        "If an AI security event cannot be observed and reconstructed, "
        "it cannot be reliably investigated or improved."
    )


if __name__ == "__main__":
    main()