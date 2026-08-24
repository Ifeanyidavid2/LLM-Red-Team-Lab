"""
Day 27 Lab 9
Incident Timeline Reconstruction & Attack-Chain Correlation

Purpose:
Reconstruct a multi-stage synthetic AI security incident across prompt,
RAG, memory, agent, authorization, and tool-execution telemetry.

The lab demonstrates:
- Stable incident correlation
- Cross-session reconstruction
- Cross-agent reconstruction
- Ordered timeline generation
- Attack-stage mapping
- Root-cause identification
- Blast-radius analysis
- Evidence hashing
- Time-to-detection measurement

Core Principle:
If an AI security event cannot be observed and reconstructed,
it cannot be reliably investigated or improved.
"""

import json
import hashlib
from datetime import datetime, timezone, timedelta


# ============================================================
# CONFIGURATION
# ============================================================

INCIDENT_ID = "INC-2709"
TRACE_ID = "TRACE-2709"

TRUSTED_RECORD = "R-2702"
RESTRICTED_RECORD = "R-2799"

MEMORY_STORE = "MEMORY-2701"

SESSION_1 = "SESSION-2701"
SESSION_2 = "SESSION-2702"

AGENT_1 = "AGENT-2701"
AGENT_2 = "AGENT-2702"


# ============================================================
# HELPERS
# ============================================================

def iso_time(base, seconds):
    return (
        base
        + timedelta(seconds=seconds)
    ).isoformat()


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


def rate(numerator, denominator):
    if denominator == 0:
        return 0.0

    return numerator / denominator * 100


# ============================================================
# SYNTHETIC INCIDENT START
# ============================================================

BASE_TIME = datetime(
    2026,
    8,
    24,
    17,
    50,
    0,
    tzinfo=timezone.utc,
)


# ============================================================
# ATTACK STAGES
# ============================================================

EXPECTED_STAGES = [
    "INITIAL_PROMPT_INJECTION",
    "POISONED_RAG_RETRIEVAL",
    "POISONED_CONTEXT_ADMISSION",
    "UNAUTHORIZED_MEMORY_WRITE",
    "MEMORY_PERSISTENCE",
    "CROSS_SESSION_MEMORY_RETRIEVAL",
    "AGENT_PLAN_MANIPULATION",
    "RESTRICTED_TARGET_SELECTION",
    "PRIVILEGED_TOOL_SELECTION",
    "AUTHORIZATION_FAILURE",
    "AUTHORIZATION_BYPASS",
    "UNAUTHORIZED_TOOL_EXECUTION",
    "UNAUTHORIZED_SYSTEM_IMPACT",
    "SECURITY_ALERT",
    "INCIDENT_DECLARATION",
]


# ============================================================
# RAW TELEMETRY EVENTS
# ============================================================

RAW_EVENTS = [
    {
        "sequence": 1,
        "timestamp": iso_time(BASE_TIME, 0),
        "session_id": SESSION_1,
        "agent_id": AGENT_1,
        "component": "input_gateway",
        "event_type": "prompt_received",
        "attack_stage": "INITIAL_PROMPT_INJECTION",
        "details": {
            "prompt_classification": "suspicious",
            "indicator": "instruction_override",
        },
    },

    {
        "sequence": 2,
        "timestamp": iso_time(BASE_TIME, 2),
        "session_id": SESSION_1,
        "agent_id": AGENT_1,
        "component": "retrieval_service",
        "event_type": "rag_retrieval",
        "attack_stage": "POISONED_RAG_RETRIEVAL",
        "details": {
            "document_id": "DOC-2791",
            "source": "external_untrusted_upload",
            "poison_detected": True,
        },
    },

    {
        "sequence": 3,
        "timestamp": iso_time(BASE_TIME, 4),
        "session_id": SESSION_1,
        "agent_id": AGENT_1,
        "component": "context_security_gateway",
        "event_type": "context_admission",
        "attack_stage": "POISONED_CONTEXT_ADMISSION",
        "details": {
            "document_id": "DOC-2791",
            "admitted": True,
            "trusted": False,
        },
    },

    {
        "sequence": 4,
        "timestamp": iso_time(BASE_TIME, 7),
        "session_id": SESSION_1,
        "agent_id": AGENT_1,
        "component": "memory_service",
        "event_type": "memory_write",
        "attack_stage": "UNAUTHORIZED_MEMORY_WRITE",
        "details": {
            "memory_store": MEMORY_STORE,
            "authorized": False,
            "source": "poisoned_rag_context",
        },
    },

    {
        "sequence": 5,
        "timestamp": iso_time(BASE_TIME, 8),
        "session_id": SESSION_1,
        "agent_id": AGENT_1,
        "component": "memory_service",
        "event_type": "memory_persistence",
        "attack_stage": "MEMORY_PERSISTENCE",
        "details": {
            "memory_store": MEMORY_STORE,
            "persistent": True,
        },
    },

    {
        "sequence": 6,
        "timestamp": iso_time(BASE_TIME, 180),
        "session_id": SESSION_2,
        "agent_id": AGENT_2,
        "component": "memory_service",
        "event_type": "memory_read",
        "attack_stage": "CROSS_SESSION_MEMORY_RETRIEVAL",
        "details": {
            "memory_store": MEMORY_STORE,
            "source_session": SESSION_1,
            "retrieved": True,
        },
    },

    {
        "sequence": 7,
        "timestamp": iso_time(BASE_TIME, 182),
        "session_id": SESSION_2,
        "agent_id": AGENT_2,
        "component": "agent_planner",
        "event_type": "agent_plan",
        "attack_stage": "AGENT_PLAN_MANIPULATION",
        "details": {
            "plan_influenced_by_memory": True,
            "proposed_target": RESTRICTED_RECORD,
            "proposed_tool": "delete_record",
        },
    },

    {
        "sequence": 8,
        "timestamp": iso_time(BASE_TIME, 184),
        "session_id": SESSION_2,
        "agent_id": AGENT_2,
        "component": "tool_router",
        "event_type": "target_selection",
        "attack_stage": "RESTRICTED_TARGET_SELECTION",
        "details": {
            "trusted_target": TRUSTED_RECORD,
            "selected_target": RESTRICTED_RECORD,
            "restricted": True,
        },
    },

    {
        "sequence": 9,
        "timestamp": iso_time(BASE_TIME, 185),
        "session_id": SESSION_2,
        "agent_id": AGENT_2,
        "component": "tool_router",
        "event_type": "tool_selected",
        "attack_stage": "PRIVILEGED_TOOL_SELECTION",
        "details": {
            "tool": "delete_record",
            "privileged": True,
        },
    },

    {
        "sequence": 10,
        "timestamp": iso_time(BASE_TIME, 187),
        "session_id": SESSION_2,
        "agent_id": AGENT_2,
        "component": "authorization_service",
        "event_type": "authorization_check",
        "attack_stage": "AUTHORIZATION_FAILURE",
        "details": {
            "authorized": False,
            "tool": "delete_record",
            "target": RESTRICTED_RECORD,
        },
    },

    {
        "sequence": 11,
        "timestamp": iso_time(BASE_TIME, 188),
        "session_id": SESSION_2,
        "agent_id": AGENT_2,
        "component": "tool_runtime",
        "event_type": "authorization_bypass",
        "attack_stage": "AUTHORIZATION_BYPASS",
        "details": {
            "authorization_required": True,
            "authorization_result": False,
            "execution_continued": True,
        },
    },

    {
        "sequence": 12,
        "timestamp": iso_time(BASE_TIME, 189),
        "session_id": SESSION_2,
        "agent_id": AGENT_2,
        "component": "tool_runtime",
        "event_type": "tool_execution",
        "attack_stage": "UNAUTHORIZED_TOOL_EXECUTION",
        "details": {
            "tool": "delete_record",
            "target": RESTRICTED_RECORD,
            "executed": True,
            "authorized": False,
        },
    },

    {
        "sequence": 13,
        "timestamp": iso_time(BASE_TIME, 190),
        "session_id": SESSION_2,
        "agent_id": AGENT_2,
        "component": "record_service",
        "event_type": "security_impact",
        "attack_stage": "UNAUTHORIZED_SYSTEM_IMPACT",
        "details": {
            "target": RESTRICTED_RECORD,
            "impact_type": "unauthorized_record_deletion",
            "impact": True,
        },
    },

    {
        "sequence": 14,
        "timestamp": iso_time(BASE_TIME, 192),
        "session_id": SESSION_2,
        "agent_id": AGENT_2,
        "component": "detection_engine",
        "event_type": "security_alert",
        "attack_stage": "SECURITY_ALERT",
        "details": {
            "alert_id": "ALERT-2709",
            "severity": "critical",
        },
    },

    {
        "sequence": 15,
        "timestamp": iso_time(BASE_TIME, 195),
        "session_id": SESSION_2,
        "agent_id": AGENT_2,
        "component": "incident_response_service",
        "event_type": "incident_created",
        "attack_stage": "INCIDENT_DECLARATION",
        "details": {
            "incident_id": INCIDENT_ID,
            "severity": "critical",
            "status": "open",
        },
    },
]


# ============================================================
# ENRICH EVENTS
# ============================================================

def enrich_events(events):

    enriched = []

    previous_hash = "GENESIS"

    for event in events:

        item = {
            **event,
            "incident_id": INCIDENT_ID,
            "trace_id": TRACE_ID,
            "previous_event_hash": previous_hash,
        }

        item_hash = sha256_value(item)

        item["event_hash"] = item_hash

        enriched.append(item)

        previous_hash = item_hash

    return enriched


EVENTS = enrich_events(RAW_EVENTS)


# ============================================================
# INTEGRITY VALIDATION
# ============================================================

def verify_event_integrity(events):

    valid = 0

    for event in events:

        event_copy = dict(event)

        stored_hash = event_copy.pop(
            "event_hash"
        )

        calculated = sha256_value(
            event_copy
        )

        if stored_hash == calculated:
            valid += 1

    return valid


def verify_hash_chain(events):

    for index, event in enumerate(events):

        expected = (
            "GENESIS"
            if index == 0
            else events[
                index - 1
            ][
                "event_hash"
            ]
        )

        if (
            event[
                "previous_event_hash"
            ]
            != expected
        ):
            return False

    return True


# ============================================================
# TIMELINE RECONSTRUCTION
# ============================================================

def reconstruct_timeline(events):

    return sorted(
        events,
        key=lambda item:
            item["sequence"],
    )


TIMELINE = reconstruct_timeline(
    EVENTS
)


# ============================================================
# STAGE RECONSTRUCTION
# ============================================================

observed_stages = [
    event["attack_stage"]
    for event in TIMELINE
]

missing_stages = [
    stage
    for stage in EXPECTED_STAGES
    if stage not in observed_stages
]

stage_reconstruction_rate = rate(
    len(
        EXPECTED_STAGES
    )
    - len(
        missing_stages
    ),
    len(
        EXPECTED_STAGES
    ),
)


# ============================================================
# CORRELATION ANALYSIS
# ============================================================

incident_ids = {
    event["incident_id"]
    for event in EVENTS
}

trace_ids = {
    event["trace_id"]
    for event in EVENTS
}

sessions = sorted({
    event["session_id"]
    for event in EVENTS
})

agents = sorted({
    event["agent_id"]
    for event in EVENTS
})

components = sorted({
    event["component"]
    for event in EVENTS
})


correlated_events = sum(
    event["incident_id"]
    == INCIDENT_ID
    and
    event["trace_id"]
    == TRACE_ID
    for event in EVENTS
)

event_correlation_rate = rate(
    correlated_events,
    len(EVENTS),
)


# ============================================================
# ROOT CAUSE
# ============================================================

root_cause_event = next(
    event
    for event in TIMELINE
    if event[
        "attack_stage"
    ]
    == "INITIAL_PROMPT_INJECTION"
)

root_cause = {
    "event_id":
        root_cause_event[
            "sequence"
        ],

    "stage":
        root_cause_event[
            "attack_stage"
        ],

    "component":
        root_cause_event[
            "component"
        ],

    "reason":
        (
            "Initial prompt injection introduced "
            "untrusted instructions that led to "
            "poisoned RAG context and persistent "
            "memory compromise."
        ),
}


# ============================================================
# BLAST RADIUS
# ============================================================

blast_radius = {
    "affected_sessions":
        sessions,

    "affected_session_count":
        len(sessions),

    "affected_agents":
        agents,

    "affected_agent_count":
        len(agents),

    "affected_components":
        components,

    "affected_component_count":
        len(components),

    "affected_memory_stores": [
        MEMORY_STORE
    ],

    "affected_targets": [
        RESTRICTED_RECORD
    ],

    "privileged_tools": [
        "delete_record"
    ],

    "unauthorized_impact":
        True,

    "impact_type":
        "unauthorized_record_deletion",
}


# ============================================================
# TIME-TO-DETECTION
# ============================================================

initial_attack_time = datetime.fromisoformat(
    next(
        event["timestamp"]
        for event in EVENTS
        if event[
            "attack_stage"
        ]
        == "INITIAL_PROMPT_INJECTION"
    )
)

alert_time = datetime.fromisoformat(
    next(
        event["timestamp"]
        for event in EVENTS
        if event[
            "attack_stage"
        ]
        == "SECURITY_ALERT"
    )
)

incident_time = datetime.fromisoformat(
    next(
        event["timestamp"]
        for event in EVENTS
        if event[
            "attack_stage"
        ]
        == "INCIDENT_DECLARATION"
    )
)

time_to_detection_seconds = (
    alert_time
    - initial_attack_time
).total_seconds()

time_to_incident_seconds = (
    incident_time
    - initial_attack_time
).total_seconds()


# ============================================================
# FORENSIC METRICS
# ============================================================

valid_integrity_events = (
    verify_event_integrity(
        EVENTS
    )
)

evidence_integrity_rate = rate(
    valid_integrity_events,
    len(EVENTS),
)

hash_chain_valid = (
    verify_hash_chain(
        EVENTS
    )
)

timeline_complete = (
    len(TIMELINE)
    == len(EVENTS)
)

root_cause_identified = (
    root_cause is not None
)


# ============================================================
# OUTPUT
# ============================================================

print(
    "\n=== Day 27 Lab 9: "
    "Incident Timeline Reconstruction & "
    "Attack-Chain Correlation ==="
)


print(
    "\n"
    + "=" * 80
)

print(
    "        RECONSTRUCTED INCIDENT TIMELINE"
)

print(
    "=" * 80
)


for event in TIMELINE:

    print(
        f"{event['sequence']:02d} | "
        f"{event['timestamp']} | "
        f"{event['session_id']} | "
        f"{event['agent_id']} | "
        f"{event['attack_stage']}"
    )

    print(
        f"     Component: "
        f"{event['component']}"
    )

    print(
        f"     Event Type: "
        f"{event['event_type']}"
    )


# ============================================================
# CORRELATION SUMMARY
# ============================================================

print(
    "\n"
    + "=" * 80
)

print(
    "        ATTACK-CHAIN CORRELATION SUMMARY"
)

print(
    "=" * 80
)


print(
    "Incident ID:",
    INCIDENT_ID
)

print(
    "Trace ID:",
    TRACE_ID
)

print(
    "Total Events:",
    len(EVENTS)
)

print(
    "Correlated Events:",
    correlated_events
)

print(
    "Event Correlation Rate:",
    f"{event_correlation_rate:.2f}%"
)

print(
    "Expected Attack Stages:",
    len(
        EXPECTED_STAGES
    )
)

print(
    "Observed Attack Stages:",
    len(
        set(
            observed_stages
        )
    )
)

print(
    "Missing Attack Stages:",
    missing_stages
)

print(
    "Attack-Stage Reconstruction Rate:",
    f"{stage_reconstruction_rate:.2f}%"
)


# ============================================================
# ROOT CAUSE
# ============================================================

print(
    "\n"
    + "=" * 80
)

print(
    "        ROOT-CAUSE ANALYSIS"
)

print(
    "=" * 80
)


print(
    "Root Cause Identified:",
    root_cause_identified
)

print(
    "Initial Attack Stage:",
    root_cause[
        "stage"
    ]
)

print(
    "Initial Component:",
    root_cause[
        "component"
    ]
)

print(
    "Root-Cause Interpretation:"
)

print(
    root_cause[
        "reason"
    ]
)


# ============================================================
# BLAST RADIUS
# ============================================================

print(
    "\n"
    + "=" * 80
)

print(
    "        INCIDENT BLAST-RADIUS ANALYSIS"
)

print(
    "=" * 80
)


print(
    "Affected Sessions:",
    blast_radius[
        "affected_sessions"
    ]
)

print(
    "Affected Session Count:",
    blast_radius[
        "affected_session_count"
    ]
)

print(
    "Affected Agents:",
    blast_radius[
        "affected_agents"
    ]
)

print(
    "Affected Agent Count:",
    blast_radius[
        "affected_agent_count"
    ]
)

print(
    "Affected Components:",
    blast_radius[
        "affected_components"
    ]
)

print(
    "Affected Component Count:",
    blast_radius[
        "affected_component_count"
    ]
)

print(
    "Affected Memory Stores:",
    blast_radius[
        "affected_memory_stores"
    ]
)

print(
    "Affected Targets:",
    blast_radius[
        "affected_targets"
    ]
)

print(
    "Privileged Tools:",
    blast_radius[
        "privileged_tools"
    ]
)

print(
    "Unauthorized Impact:",
    blast_radius[
        "unauthorized_impact"
    ]
)

print(
    "Impact Type:",
    blast_radius[
        "impact_type"
    ]
)


# ============================================================
# DETECTION TIMING
# ============================================================

print(
    "\n"
    + "=" * 80
)

print(
    "        DETECTION & RESPONSE TIMING"
)

print(
    "=" * 80
)


print(
    "Initial Attack Time:",
    initial_attack_time.isoformat()
)

print(
    "Security Alert Time:",
    alert_time.isoformat()
)

print(
    "Incident Declaration Time:",
    incident_time.isoformat()
)

print(
    "Time To Detection:",
    f"{time_to_detection_seconds:.2f} seconds"
)

print(
    "Time To Incident Declaration:",
    f"{time_to_incident_seconds:.2f} seconds"
)


# ============================================================
# EVIDENCE QUALITY
# ============================================================

print(
    "\n"
    + "=" * 80
)

print(
    "        FORENSIC EVIDENCE QUALITY"
)

print(
    "=" * 80
)


print(
    "Evidence Events:",
    len(EVENTS)
)

print(
    "Valid Integrity Events:",
    valid_integrity_events
)

print(
    "Evidence Integrity Rate:",
    f"{evidence_integrity_rate:.2f}%"
)

print(
    "Hash Chain Valid:",
    hash_chain_valid
)

print(
    "Timeline Complete:",
    timeline_complete
)

print(
    "Single Incident Correlation:",
    len(
        incident_ids
    )
    == 1
)

print(
    "Single Trace Correlation:",
    len(
        trace_ids
    )
    == 1
)


# ============================================================
# FORENSIC READINESS CHECKS
# ============================================================

forensic_ready = all([
    event_correlation_rate
    == 100.0,

    stage_reconstruction_rate
    == 100.0,

    evidence_integrity_rate
    == 100.0,

    hash_chain_valid,

    timeline_complete,

    root_cause_identified,

    len(
        incident_ids
    )
    == 1,

    len(
        trace_ids
    )
    == 1,
])


print(
    "\n"
    + "=" * 80
)

print(
    "        INCIDENT RECONSTRUCTION CHECKS"
)

print(
    "=" * 80
)


print(
    "All Events Correlated:",
    event_correlation_rate
    == 100.0
)

print(
    "All Attack Stages Reconstructed:",
    stage_reconstruction_rate
    == 100.0
)

print(
    "Evidence Integrity Verified:",
    evidence_integrity_rate
    == 100.0
)

print(
    "Hash-Linked Evidence Chain Valid:",
    hash_chain_valid
)

print(
    "Timeline Reconstruction Complete:",
    timeline_complete
)

print(
    "Root Cause Identified:",
    root_cause_identified
)

print(
    "Cross-Session Impact Identified:",
    len(
        sessions
    )
    > 1
)

print(
    "Cross-Agent Impact Identified:",
    len(
        agents
    )
    > 1
)

print(
    "Incident Reconstruction Baseline Valid:",
    forensic_ready
)


# ============================================================
# EVIDENCE EXPORT
# ============================================================

evidence = {
    "lab":
        "Day 27 Lab 9",

    "title":
        (
            "Incident Timeline Reconstruction "
            "& Attack-Chain Correlation"
        ),

    "incident_id":
        INCIDENT_ID,

    "trace_id":
        TRACE_ID,

    "expected_attack_stages":
        EXPECTED_STAGES,

    "timeline":
        TIMELINE,

    "correlation": {
        "total_events":
            len(EVENTS),

        "correlated_events":
            correlated_events,

        "event_correlation_rate":
            event_correlation_rate,

        "attack_stage_reconstruction_rate":
            stage_reconstruction_rate,

        "missing_attack_stages":
            missing_stages,
    },

    "root_cause":
        root_cause,

    "blast_radius":
        blast_radius,

    "timing": {
        "initial_attack_time":
            initial_attack_time.isoformat(),

        "alert_time":
            alert_time.isoformat(),

        "incident_time":
            incident_time.isoformat(),

        "time_to_detection_seconds":
            time_to_detection_seconds,

        "time_to_incident_seconds":
            time_to_incident_seconds,
    },

    "evidence_quality": {
        "evidence_integrity_rate":
            evidence_integrity_rate,

        "hash_chain_valid":
            hash_chain_valid,

        "timeline_complete":
            timeline_complete,

        "single_incident_correlation":
            len(
                incident_ids
            )
            == 1,

        "single_trace_correlation":
            len(
                trace_ids
            )
            == 1,
    },

    "security_checks": {
        "all_events_correlated":
            event_correlation_rate
            == 100.0,

        "all_stages_reconstructed":
            stage_reconstruction_rate
            == 100.0,

        "evidence_integrity_verified":
            evidence_integrity_rate
            == 100.0,

        "hash_chain_valid":
            hash_chain_valid,

        "timeline_complete":
            timeline_complete,

        "root_cause_identified":
            root_cause_identified,

        "cross_session_impact_identified":
            len(
                sessions
            )
            > 1,

        "cross_agent_impact_identified":
            len(
                agents
            )
            > 1,

        "forensic_baseline_valid":
            forensic_ready,
    },
}


evidence_file = (
    "day27-incident-timeline-correlation-evidence.json"
)


with open(
    evidence_file,
    "w",
    encoding="utf-8",
) as file:

    json.dump(
        evidence,
        file,
        indent=2,
    )


print(
    "\nEvidence written to:"
)

print(
    evidence_file
)


# ============================================================
# INTERPRETATION
# ============================================================

print(
    "\nSecurity Interpretation:"
)

print(
    "The incident reconstruction process correlates "
    "security telemetry across prompt ingestion, RAG retrieval, "
    "context admission, persistent memory, a later session, "
    "agent planning, target selection, privileged tool use, "
    "authorization failure, authorization bypass, execution, "
    "and system impact."
)

print(
    "The reconstructed sequence demonstrates that an AI "
    "incident cannot be understood from a single alert alone; "
    "cross-component and cross-session correlation is required "
    "to identify root cause and blast radius."
)

print(
    "Cryptographically linked evidence, stable incident and "
    "trace identifiers, ordered timestamps, attack-stage labels, "
    "and affected-asset metadata support reproducible forensic "
    "analysis."
)


print(
    "\nCore Principle:"
)

print(
    "If an AI security event cannot be observed and reconstructed, "
    "it cannot be reliably investigated or improved."
)