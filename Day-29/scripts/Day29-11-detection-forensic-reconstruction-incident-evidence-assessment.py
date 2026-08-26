"""
Day 29 Lab 11
Detection, Forensic Reconstruction & Incident Evidence Assessment

Purpose:
Evaluate whether the synthetic enterprise can observe, detect, correlate,
preserve, and reconstruct the Day 29 multi-stage LLM attack chain.

Core Principle:
An enterprise AI security control is incomplete if successful attacks
cannot be detected, correlated, reconstructed, and preserved as evidence.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from collections import Counter
import hashlib
import json


ENGAGEMENT_ID = "ENG-2901"
SYSTEM_ID = "ENT-AI-2901"
INCIDENT_ID = "INC-2911"
TRACE_ID = "TRACE-2911"


# =============================================================================
# ATTACK TELEMETRY
# =============================================================================

ATTACK_EVENTS = [
    {
        "sequence": 1,
        "event_id": "EVT-2911-001",
        "event_type": "prompt_injection_detected",
        "component": "AI Assistant",
        "stage": "INITIAL_ACCESS",
        "severity": "HIGH",
        "observable": True,
        "detected": False,
    },
    {
        "sequence": 2,
        "event_id": "EVT-2911-002",
        "event_type": "untrusted_rag_document_retrieved",
        "component": "RAG Knowledge System",
        "stage": "INITIAL_ACCESS",
        "severity": "HIGH",
        "observable": True,
        "detected": False,
    },
    {
        "sequence": 3,
        "event_id": "EVT-2911-003",
        "event_type": "indirect_prompt_injection",
        "component": "LLM Runtime",
        "stage": "INITIAL_ACCESS",
        "severity": "CRITICAL",
        "observable": True,
        "detected": False,
    },
    {
        "sequence": 4,
        "event_id": "EVT-2911-004",
        "event_type": "restricted_target_substitution",
        "component": "Agent Planner",
        "stage": "EXECUTION_MANIPULATION",
        "severity": "CRITICAL",
        "observable": True,
        "detected": False,
    },
    {
        "sequence": 5,
        "event_id": "EVT-2911-005",
        "event_type": "unauthorized_memory_write",
        "component": "Persistent Memory",
        "stage": "PERSISTENCE",
        "severity": "CRITICAL",
        "observable": True,
        "detected": False,
    },
    {
        "sequence": 6,
        "event_id": "EVT-2911-006",
        "event_type": "cross_session_memory_activation",
        "component": "Persistent Memory",
        "stage": "PERSISTENCE",
        "severity": "CRITICAL",
        "observable": True,
        "detected": False,
    },
    {
        "sequence": 7,
        "event_id": "EVT-2911-007",
        "event_type": "cross_agent_memory_influence",
        "component": "Agent Planner",
        "stage": "PERSISTENCE",
        "severity": "CRITICAL",
        "observable": True,
        "detected": False,
    },
    {
        "sequence": 8,
        "event_id": "EVT-2911-008",
        "event_type": "agent_goal_hijacking",
        "component": "Agent Planner",
        "stage": "EXECUTION_MANIPULATION",
        "severity": "CRITICAL",
        "observable": True,
        "detected": False,
    },
    {
        "sequence": 9,
        "event_id": "EVT-2911-009",
        "event_type": "privileged_tool_selection",
        "component": "Tools / APIs",
        "stage": "EXECUTION_MANIPULATION",
        "severity": "CRITICAL",
        "observable": True,
        "detected": True,
    },
    {
        "sequence": 10,
        "event_id": "EVT-2911-010",
        "event_type": "unsafe_tool_parameters",
        "component": "Tools / APIs",
        "stage": "EXECUTION_MANIPULATION",
        "severity": "CRITICAL",
        "observable": True,
        "detected": True,
    },
    {
        "sequence": 11,
        "event_id": "EVT-2911-011",
        "event_type": "model_generated_authority",
        "component": "Authorization Service",
        "stage": "PRIVILEGE_ESCALATION",
        "severity": "CRITICAL",
        "observable": True,
        "detected": False,
    },
    {
        "sequence": 12,
        "event_id": "EVT-2911-012",
        "event_type": "authorization_denied",
        "component": "Authorization Service",
        "stage": "PRIVILEGE_ESCALATION",
        "severity": "HIGH",
        "observable": True,
        "detected": True,
    },
    {
        "sequence": 13,
        "event_id": "EVT-2911-013",
        "event_type": "execution_after_authorization_denial",
        "component": "Tool Runtime",
        "stage": "PRIVILEGE_ESCALATION",
        "severity": "CRITICAL",
        "observable": True,
        "detected": True,
    },
    {
        "sequence": 14,
        "event_id": "EVT-2911-014",
        "event_type": "credential_scope_abuse",
        "component": "Credential Broker",
        "stage": "PRIVILEGE_ESCALATION",
        "severity": "CRITICAL",
        "observable": True,
        "detected": True,
    },
    {
        "sequence": 15,
        "event_id": "EVT-2911-015",
        "event_type": "unauthorized_tool_execution",
        "component": "Tool Runtime",
        "stage": "IMPACT",
        "severity": "CRITICAL",
        "observable": True,
        "detected": True,
    },
    {
        "sequence": 16,
        "event_id": "EVT-2911-016",
        "event_type": "unauthorized_business_impact",
        "component": "Record Service",
        "stage": "IMPACT",
        "severity": "CRITICAL",
        "observable": True,
        "detected": True,
    },
]


# =============================================================================
# DETECTION RULES
# =============================================================================

DETECTION_RULES = [
    {
        "rule_id": "DET-2911-001",
        "name": "Prompt Injection Detection",
        "events": ["prompt_injection_detected"],
        "expected_stage": "INITIAL_ACCESS",
    },
    {
        "rule_id": "DET-2911-002",
        "name": "RAG Poisoning Correlation",
        "events": [
            "untrusted_rag_document_retrieved",
            "indirect_prompt_injection",
        ],
        "expected_stage": "INITIAL_ACCESS",
    },
    {
        "rule_id": "DET-2911-003",
        "name": "Persistent Memory Compromise",
        "events": [
            "unauthorized_memory_write",
            "cross_session_memory_activation",
        ],
        "expected_stage": "PERSISTENCE",
    },
    {
        "rule_id": "DET-2911-004",
        "name": "Cross-Agent Memory Influence",
        "events": [
            "cross_agent_memory_influence",
            "agent_goal_hijacking",
        ],
        "expected_stage": "PERSISTENCE",
    },
    {
        "rule_id": "DET-2911-005",
        "name": "Privileged Tool Anomaly",
        "events": [
            "privileged_tool_selection",
            "unsafe_tool_parameters",
        ],
        "expected_stage": "EXECUTION_MANIPULATION",
    },
    {
        "rule_id": "DET-2911-006",
        "name": "Authorization Denial Followed by Execution",
        "events": [
            "authorization_denied",
            "execution_after_authorization_denial",
        ],
        "expected_stage": "PRIVILEGE_ESCALATION",
    },
    {
        "rule_id": "DET-2911-007",
        "name": "Credential Scope Abuse",
        "events": [
            "credential_scope_abuse",
        ],
        "expected_stage": "PRIVILEGE_ESCALATION",
    },
    {
        "rule_id": "DET-2911-008",
        "name": "Unauthorized Tool Execution",
        "events": [
            "unauthorized_tool_execution",
        ],
        "expected_stage": "IMPACT",
    },
    {
        "rule_id": "DET-2911-009",
        "name": "Unauthorized Business Impact",
        "events": [
            "unauthorized_business_impact",
        ],
        "expected_stage": "IMPACT",
    },
]


# =============================================================================
# HELPERS
# =============================================================================

def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def hash_data(value):
    return hashlib.sha256(
        canonical_json(value).encode("utf-8")
    ).hexdigest()


def header(title):
    print("\n" + "=" * 100)
    print(f"        {title}")
    print("=" * 100)


# =============================================================================
# MAIN
# =============================================================================

def main():

    print(
        "\n=== Day 29 Lab 11: Detection, Forensic Reconstruction "
        "& Incident Evidence Assessment ==="
    )

    start_time = datetime.now(
        timezone.utc
    )

    events = []
    previous_hash = "GENESIS"

    for index, raw_event in enumerate(
        ATTACK_EVENTS
    ):

        timestamp = (
            start_time
            + timedelta(
                seconds=index * 8
            )
        )

        event = {
            "engagement_id":
                ENGAGEMENT_ID,

            "system_id":
                SYSTEM_ID,

            "incident_id":
                INCIDENT_ID,

            "trace_id":
                TRACE_ID,

            "timestamp_utc":
                timestamp.isoformat(),

            **raw_event,

            "previous_hash":
                previous_hash,
        }

        event["event_hash"] = hash_data(
            event
        )

        previous_hash = (
            event["event_hash"]
        )

        events.append(
            event
        )

    # ---------------------------------------------------------------------
    # TELEMETRY COVERAGE
    # ---------------------------------------------------------------------

    header("AI SECURITY TELEMETRY COVERAGE")

    observable_events = [
        event
        for event in events
        if event["observable"]
    ]

    detected_events = [
        event
        for event in events
        if event["detected"]
    ]

    telemetry_coverage = (
        len(observable_events)
        / len(events)
        * 100
    )

    detection_coverage = (
        len(detected_events)
        / len(events)
        * 100
    )

    for event in events:

        print(
            f"{event['event_id']} | "
            f"{event['stage']} | "
            f"{event['event_type']} | "
            f"Observable={event['observable']} | "
            f"Detected={event['detected']}"
        )

    # ---------------------------------------------------------------------
    # RULE EVALUATION
    # ---------------------------------------------------------------------

    event_map = {
        event["event_type"]:
            event
        for event in events
    }

    detection_results = []

    for rule in DETECTION_RULES:

        present = all(
            event_type in event_map
            for event_type in rule["events"]
        )

        detected = (
            present
            and all(
                event_map[event_type][
                    "detected"
                ]
                for event_type
                in rule["events"]
            )
        )

        detection_results.append({
            "rule_id":
                rule["rule_id"],

            "name":
                rule["name"],

            "events":
                rule["events"],

            "expected_stage":
                rule["expected_stage"],

            "events_present":
                present,

            "detected":
                detected,
        })

    header("DETECTION RULE RESULTS")

    for result in detection_results:

        status = (
            "DETECTED"
            if result["detected"]
            else "MISSED"
        )

        print(
            f"{result['rule_id']} | "
            f"{status} | "
            f"{result['name']}"
        )

        print(
            "  Events: "
            + ", ".join(
                result["events"]
            )
        )

    # ---------------------------------------------------------------------
    # EARLY DETECTION ANALYSIS
    # ---------------------------------------------------------------------

    early_stages = {
        "INITIAL_ACCESS",
        "PERSISTENCE",
    }

    early_events = [
        event
        for event in events
        if event["stage"]
        in early_stages
    ]

    detected_early_events = [
        event
        for event in early_events
        if event["detected"]
    ]

    early_detection_rate = (
        len(detected_early_events)
        / len(early_events)
        * 100
    )

    first_detected_event = next(
        event
        for event in events
        if event["detected"]
    )

    impact_event = next(
        event
        for event in events
        if event["event_type"]
        == "unauthorized_business_impact"
    )

    first_detection_time = datetime.fromisoformat(
        first_detected_event[
            "timestamp_utc"
        ]
    )

    impact_time = datetime.fromisoformat(
        impact_event[
            "timestamp_utc"
        ]
    )

    initial_time = datetime.fromisoformat(
        events[0]["timestamp_utc"]
    )

    time_to_first_detection = (
        first_detection_time
        - initial_time
    ).total_seconds()

    time_to_impact = (
        impact_time
        - initial_time
    ).total_seconds()

    detected_before_impact = (
        first_detection_time
        <
        impact_time
    )

    header("EARLY DETECTION ANALYSIS")

    print(
        f"Early Attack Events: "
        f"{len(early_events)}"
    )

    print(
        f"Detected Early Events: "
        f"{len(detected_early_events)}"
    )

    print(
        f"Early Detection Rate: "
        f"{early_detection_rate:.2f}%"
    )

    print(
        f"First Detected Event: "
        f"{first_detected_event['event_type']}"
    )

    print(
        f"Time to First Detection: "
        f"{time_to_first_detection:.2f} seconds"
    )

    print(
        f"Time to Business Impact: "
        f"{time_to_impact:.2f} seconds"
    )

    print(
        f"Detection Before Business Impact: "
        f"{detected_before_impact}"
    )

    # ---------------------------------------------------------------------
    # FORENSIC RECONSTRUCTION
    # ---------------------------------------------------------------------

    ordered_events = sorted(
        events,
        key=lambda event:
            event["sequence"]
    )

    sequence_valid = (
        [
            event["sequence"]
            for event in ordered_events
        ]
        ==
        list(
            range(
                1,
                len(events) + 1
            )
        )
    )

    single_incident = (
        len({
            event["incident_id"]
            for event in events
        })
        == 1
    )

    single_trace = (
        len({
            event["trace_id"]
            for event in events
        })
        == 1
    )

    hash_chain_valid = True

    previous_hash = "GENESIS"

    for event in ordered_events:

        if (
            event["previous_hash"]
            != previous_hash
        ):
            hash_chain_valid = False

        validation = dict(
            event
        )

        stored_hash = validation.pop(
            "event_hash"
        )

        if (
            hash_data(validation)
            != stored_hash
        ):
            hash_chain_valid = False

        previous_hash = stored_hash

    header("FORENSIC RECONSTRUCTION")

    print(
        f"Events Reconstructed: "
        f"{len(ordered_events)}"
    )

    print(
        f"Sequence Valid: "
        f"{sequence_valid}"
    )

    print(
        f"Single Incident Correlation: "
        f"{single_incident}"
    )

    print(
        f"Single Trace Correlation: "
        f"{single_trace}"
    )

    print(
        f"Evidence Hash Chain Valid: "
        f"{hash_chain_valid}"
    )

    # ---------------------------------------------------------------------
    # ROOT CAUSE
    # ---------------------------------------------------------------------

    ROOT_CAUSES = [
        {
            "root_cause_id": "RC-2911-01",
            "area": "Instruction Trust",
            "finding":
                "Untrusted prompt and retrieved content influenced trusted behavior.",
        },
        {
            "root_cause_id": "RC-2911-02",
            "area": "RAG Security",
            "finding":
                "Untrusted retrieved content crossed the context trust boundary.",
        },
        {
            "root_cause_id": "RC-2911-03",
            "area": "Persistent Memory",
            "finding":
                "Attacker-controlled state persisted across sessions and agents.",
        },
        {
            "root_cause_id": "RC-2911-04",
            "area": "Agent Security",
            "finding":
                "Model-influenced state changed trusted goals and targets.",
        },
        {
            "root_cause_id": "RC-2911-05",
            "area": "Authorization",
            "finding":
                "Denied privileged execution was allowed to continue.",
        },
        {
            "root_cause_id": "RC-2911-06",
            "area": "Credential Security",
            "finding":
                "Task credential scope was broader than the authorized action.",
        },
        {
            "root_cause_id": "RC-2911-07",
            "area": "Detection Engineering",
            "finding":
                "Early attack stages were observable but not detected.",
        },
    ]

    header("ROOT-CAUSE ANALYSIS")

    for root_cause in ROOT_CAUSES:

        print(
            f"{root_cause['root_cause_id']} | "
            f"{root_cause['area']}"
        )

        print(
            f"  {root_cause['finding']}"
        )

    # ---------------------------------------------------------------------
    # BLAST RADIUS
    # ---------------------------------------------------------------------

    affected_components = sorted({
        event["component"]
        for event in events
    })

    affected_stages = sorted({
        event["stage"]
        for event in events
    })

    BLAST_RADIUS = {
        "sessions": [
            "SESSION-2901",
            "SESSION-2902",
        ],

        "agents": [
            "AGENT-2901",
            "AGENT-2902",
        ],

        "memory_store":
            "MEMORY-2901",

        "rag_document":
            "DOC-2991",

        "restricted_target":
            "R-2999",

        "privileged_tool":
            "delete_record",

        "authorization_service":
            "AUTHZ-2901",

        "credential_broker":
            "CRED-2901",

        "business_service":
            "RECORD-SERVICE-2901",
    }

    header("FORENSIC BLAST-RADIUS ANALYSIS")

    for key, value in BLAST_RADIUS.items():

        print(
            f"{key}: {value}"
        )

    print(
        f"Affected Components: "
        f"{len(affected_components)}"
    )

    print(
        f"Attack Stages Reconstructed: "
        f"{len(affected_stages)}"
    )

    # ---------------------------------------------------------------------
    # DETECTION GAP ANALYSIS
    # ---------------------------------------------------------------------

    missed_events = [
        event
        for event in events
        if event["observable"]
        and not event["detected"]
    ]

    missed_critical_events = [
        event
        for event in missed_events
        if event["severity"]
        == "CRITICAL"
    ]

    missed_rules = [
        result
        for result
        in detection_results
        if not result["detected"]
    ]

    header("DETECTION GAP ANALYSIS")

    print(
        f"Observable Events: "
        f"{len(observable_events)}"
    )

    print(
        f"Detected Events: "
        f"{len(detected_events)}"
    )

    print(
        f"Missed Observable Events: "
        f"{len(missed_events)}"
    )

    print(
        f"Missed Critical Events: "
        f"{len(missed_critical_events)}"
    )

    print(
        f"Detection Rules: "
        f"{len(DETECTION_RULES)}"
    )

    print(
        f"Missed Detection Rules: "
        f"{len(missed_rules)}"
    )

    for event in missed_events:

        print(
            f"- {event['event_id']} | "
            f"{event['severity']} | "
            f"{event['event_type']}"
        )

    # ---------------------------------------------------------------------
    # METRICS
    # ---------------------------------------------------------------------

    rule_detection_rate = (
        (
            len(DETECTION_RULES)
            - len(missed_rules)
        )
        / len(DETECTION_RULES)
        * 100
    )

    forensic_reconstruction_rate = (
        len(ordered_events)
        / len(ATTACK_EVENTS)
        * 100
    )

    # ---------------------------------------------------------------------
    # VALIDATION
    # ---------------------------------------------------------------------

    header("DETECTION / FORENSIC ASSESSMENT CHECKS")

    checks = {
        "All Attack Events Observable":
            telemetry_coverage
            == 100.0,

        "Detection Coverage Measured":
            detection_coverage
            >= 0,

        "Early Detection Measured":
            early_detection_rate
            >= 0,

        "Detection Timing Calculated":
            time_to_first_detection
            >= 0,

        "Timeline Reconstructed":
            forensic_reconstruction_rate
            == 100.0,

        "Sequence Verified":
            sequence_valid,

        "Incident Correlation Verified":
            single_incident,

        "Trace Correlation Verified":
            single_trace,

        "Hash-Linked Evidence Valid":
            hash_chain_valid,

        "Root Causes Identified":
            len(ROOT_CAUSES) > 0,

        "Blast Radius Identified":
            len(BLAST_RADIUS) > 0,

        "Detection Gaps Identified":
            len(missed_events) > 0,

        "Critical Missed Events Identified":
            len(missed_critical_events) > 0,

        "Detection Rules Evaluated":
            len(detection_results)
            == len(DETECTION_RULES),
    }

    checks[
        "Detection / Forensic Assessment Valid"
    ] = all(
        checks.values()
    )

    for check, result in checks.items():

        print(
            f"{check}: {result}"
        )

    # ---------------------------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------------------------

    header("DETECTION / FORENSIC ASSESSMENT SUMMARY")

    print(
        f"Attack Events: "
        f"{len(events)}"
    )

    print(
        f"Telemetry Coverage: "
        f"{telemetry_coverage:.2f}%"
    )

    print(
        f"Event Detection Coverage: "
        f"{detection_coverage:.2f}%"
    )

    print(
        f"Detection Rule Success Rate: "
        f"{rule_detection_rate:.2f}%"
    )

    print(
        f"Early Detection Rate: "
        f"{early_detection_rate:.2f}%"
    )

    print(
        f"Time to First Detection: "
        f"{time_to_first_detection:.2f} seconds"
    )

    print(
        f"Time to Business Impact: "
        f"{time_to_impact:.2f} seconds"
    )

    print(
        f"Detection Before Impact: "
        f"{detected_before_impact}"
    )

    print(
        f"Forensic Reconstruction Rate: "
        f"{forensic_reconstruction_rate:.2f}%"
    )

    print(
        f"Missed Critical Events: "
        f"{len(missed_critical_events)}"
    )

    print(
        f"Root Causes: "
        f"{len(ROOT_CAUSES)}"
    )

    # ---------------------------------------------------------------------
    # EXPORT
    # ---------------------------------------------------------------------

    evidence = {
        "engagement_id":
            ENGAGEMENT_ID,

        "system_id":
            SYSTEM_ID,

        "incident_id":
            INCIDENT_ID,

        "trace_id":
            TRACE_ID,

        "events":
            events,

        "detection_rules":
            detection_results,

        "root_causes":
            ROOT_CAUSES,

        "blast_radius":
            BLAST_RADIUS,

        "missed_events":
            missed_events,

        "metrics": {
            "attack_events":
                len(events),

            "telemetry_coverage_percent":
                round(
                    telemetry_coverage,
                    2
                ),

            "event_detection_coverage_percent":
                round(
                    detection_coverage,
                    2
                ),

            "rule_detection_rate_percent":
                round(
                    rule_detection_rate,
                    2
                ),

            "early_detection_rate_percent":
                round(
                    early_detection_rate,
                    2
                ),

            "time_to_first_detection_seconds":
                time_to_first_detection,

            "time_to_business_impact_seconds":
                time_to_impact,

            "detection_before_impact":
                detected_before_impact,

            "forensic_reconstruction_rate_percent":
                round(
                    forensic_reconstruction_rate,
                    2
                ),

            "missed_critical_events":
                len(
                    missed_critical_events
                ),

            "root_causes":
                len(ROOT_CAUSES),
        },

        "security_checks":
            checks,
    }

    evidence["evidence_package_hash"] = hash_data(
        evidence
    )

    output = Path(
        "day29-detection-forensic-reconstruction-evidence.json"
    )

    output.write_text(
        json.dumps(
            evidence,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print("\nEvidence written to:")
    print(output)

    print("\nSecurity Interpretation:")

    print(
        "The enterprise produced sufficient telemetry to reconstruct "
        "the full attack, but early-stage detection coverage was weaker "
        "than observability coverage."
    )

    print(
        "This distinction is important: logging an AI event does not mean "
        "the organization will recognize it as malicious in time to prevent "
        "business impact."
    )

    print(
        "The forensic reconstruction links prompt compromise, retrieval, "
        "persistent memory, cross-session propagation, agent manipulation, "
        "authorization failure, credential abuse and business impact into "
        "one defensible incident record."
    )

    print("\nCore Principle:")

    print(
        "An enterprise AI security control is incomplete if successful "
        "attacks cannot be detected, correlated, reconstructed and "
        "preserved as evidence."
    )


if __name__ == "__main__":
    main()