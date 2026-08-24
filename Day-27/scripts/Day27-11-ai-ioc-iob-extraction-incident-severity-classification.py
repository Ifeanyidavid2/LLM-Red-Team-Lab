"""
Day 27 Lab 11
AI Indicators of Compromise / Indicators of Behavior
& Incident Severity Classification

Purpose:
Convert synthetic AI forensic evidence into reusable detection
intelligence and classify incident severity based on observed
security impact.

Core Principle:
If an AI security event cannot be observed and reconstructed,
it cannot be reliably investigated or improved.
"""

import json
from collections import Counter


INCIDENT_ID = "INC-2711"
TRACE_ID = "TRACE-2711"


# ============================================================
# SYNTHETIC FORENSIC OBSERVATIONS
# ============================================================

OBSERVATIONS = [
    {
        "event_id": "EVT-2711-001",
        "event_type": "prompt_received",
        "component": "input_gateway",
        "indicator": "instruction_override_attempt",
        "value": "ignore_previous_instructions",
        "severity": "high",
    },
    {
        "event_id": "EVT-2711-002",
        "event_type": "rag_retrieval",
        "component": "retrieval_service",
        "indicator": "untrusted_rag_source",
        "value": "DOC-2791",
        "severity": "high",
    },
    {
        "event_id": "EVT-2711-003",
        "event_type": "context_admission",
        "component": "context_security_gateway",
        "indicator": "poisoned_context_admitted",
        "value": "R-2799",
        "severity": "high",
    },
    {
        "event_id": "EVT-2711-004",
        "event_type": "memory_write",
        "component": "memory_service",
        "indicator": "unauthorized_memory_write",
        "value": "MEMORY-2701",
        "severity": "high",
    },
    {
        "event_id": "EVT-2711-005",
        "event_type": "memory_persistence",
        "component": "memory_service",
        "indicator": "persistent_malicious_instruction",
        "value": "R-2799",
        "severity": "critical",
    },
    {
        "event_id": "EVT-2711-006",
        "event_type": "memory_read",
        "component": "memory_service",
        "indicator": "cross_session_memory_influence",
        "value": "MEMORY-2701",
        "severity": "critical",
    },
    {
        "event_id": "EVT-2711-007",
        "event_type": "agent_plan",
        "component": "agent_planner",
        "indicator": "privileged_action_proposal",
        "value": "delete_record",
        "severity": "critical",
    },
    {
        "event_id": "EVT-2711-008",
        "event_type": "target_selection",
        "component": "tool_router",
        "indicator": "restricted_target_selection",
        "value": "R-2799",
        "severity": "critical",
    },
    {
        "event_id": "EVT-2711-009",
        "event_type": "authorization_check",
        "component": "authorization_service",
        "indicator": "authorization_denied",
        "value": "delete_record:R-2799",
        "severity": "high",
    },
    {
        "event_id": "EVT-2711-010",
        "event_type": "authorization_bypass",
        "component": "tool_runtime",
        "indicator": "authorization_bypass",
        "value": "delete_record:R-2799",
        "severity": "critical",
    },
    {
        "event_id": "EVT-2711-011",
        "event_type": "tool_execution",
        "component": "tool_runtime",
        "indicator": "unauthorized_tool_execution",
        "value": "delete_record",
        "severity": "critical",
    },
    {
        "event_id": "EVT-2711-012",
        "event_type": "security_impact",
        "component": "record_service",
        "indicator": "unauthorized_system_impact",
        "value": "unauthorized_record_deletion",
        "severity": "critical",
    },
]


# ============================================================
# INDICATOR CLASSIFICATION
# ============================================================

IOC_TYPES = {
    "untrusted_rag_source",
    "persistent_malicious_instruction",
    "restricted_target_selection",
}

IOB_TYPES = {
    "instruction_override_attempt",
    "poisoned_context_admitted",
    "unauthorized_memory_write",
    "cross_session_memory_influence",
    "privileged_action_proposal",
    "authorization_denied",
    "authorization_bypass",
    "unauthorized_tool_execution",
    "unauthorized_system_impact",
}


def classify_indicator(observation):

    indicator = observation["indicator"]

    if indicator in IOC_TYPES:
        return "IOC"

    if indicator in IOB_TYPES:
        return "IOB"

    return "UNKNOWN"


# ============================================================
# EXTRACT INDICATORS
# ============================================================

INDICATORS = []

for observation in OBSERVATIONS:

    indicator_type = classify_indicator(
        observation
    )

    INDICATORS.append({
        "indicator_id":
            f"IND-{len(INDICATORS) + 1:04d}",

        "event_id":
            observation["event_id"],

        "indicator_type":
            indicator_type,

        "name":
            observation["indicator"],

        "value":
            observation["value"],

        "component":
            observation["component"],

        "severity":
            observation["severity"],
    })


# ============================================================
# INCIDENT IMPACT FACTORS
# ============================================================

IMPACT_FACTORS = {
    "prompt_injection_observed": True,
    "rag_poisoning_observed": True,
    "persistent_memory_compromise": True,
    "cross_session_propagation": True,
    "privileged_action_proposed": True,
    "authorization_bypass": True,
    "unauthorized_execution": True,
    "unauthorized_system_impact": True,
    "sensitive_information_disclosure": False,
}


# ============================================================
# SEVERITY SCORING
# ============================================================

SEVERITY_WEIGHTS = {
    "prompt_injection_observed": 5,
    "rag_poisoning_observed": 10,
    "persistent_memory_compromise": 15,
    "cross_session_propagation": 15,
    "privileged_action_proposed": 10,
    "authorization_bypass": 15,
    "unauthorized_execution": 15,
    "unauthorized_system_impact": 15,
    "sensitive_information_disclosure": 15,
}


def calculate_risk_score():

    score = 0

    for factor, active in IMPACT_FACTORS.items():

        if active:
            score += SEVERITY_WEIGHTS[factor]

    return min(score, 100)


RISK_SCORE = calculate_risk_score()


def classify_severity(score):

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    return "LOW"


INCIDENT_SEVERITY = classify_severity(
    RISK_SCORE
)


# ============================================================
# BLAST-RADIUS CLASSIFICATION
# ============================================================

BLAST_RADIUS = {
    "sessions_affected": [
        "SESSION-2701",
        "SESSION-2702",
    ],
    "agents_affected": [
        "AGENT-2701",
        "AGENT-2702",
    ],
    "memory_stores_affected": [
        "MEMORY-2701",
    ],
    "rag_documents_involved": [
        "DOC-2791",
    ],
    "restricted_targets_affected": [
        "R-2799",
    ],
    "privileged_tools_involved": [
        "delete_record",
    ],
    "cross_session": True,
    "unauthorized_impact": True,
}


# ============================================================
# DETECTION INTELLIGENCE
# ============================================================

DETECTION_INTELLIGENCE = [
    {
        "rule_id": "AI-DET-2711-001",
        "name": "Prompt Instruction Override Attempt",
        "indicator": "instruction_override_attempt",
        "priority": "high",
    },
    {
        "rule_id": "AI-DET-2711-002",
        "name": "Untrusted RAG Context Admission",
        "indicator": "poisoned_context_admitted",
        "priority": "high",
    },
    {
        "rule_id": "AI-DET-2711-003",
        "name": "Unauthorized Persistent Memory Write",
        "indicator": "unauthorized_memory_write",
        "priority": "high",
    },
    {
        "rule_id": "AI-DET-2711-004",
        "name": "Cross-Session Memory Influence",
        "indicator": "cross_session_memory_influence",
        "priority": "critical",
    },
    {
        "rule_id": "AI-DET-2711-005",
        "name": "Privileged Tool Proposal",
        "indicator": "privileged_action_proposal",
        "priority": "critical",
    },
    {
        "rule_id": "AI-DET-2711-006",
        "name": "Authorization Bypass",
        "indicator": "authorization_bypass",
        "priority": "critical",
    },
    {
        "rule_id": "AI-DET-2711-007",
        "name": "Unauthorized Tool Execution",
        "indicator": "unauthorized_tool_execution",
        "priority": "critical",
    },
    {
        "rule_id": "AI-DET-2711-008",
        "name": "Unauthorized AI System Impact",
        "indicator": "unauthorized_system_impact",
        "priority": "critical",
    },
]


# ============================================================
# METRICS
# ============================================================

ioc_count = sum(
    1 for item in INDICATORS
    if item["indicator_type"] == "IOC"
)

iob_count = sum(
    1 for item in INDICATORS
    if item["indicator_type"] == "IOB"
)

unknown_count = sum(
    1 for item in INDICATORS
    if item["indicator_type"] == "UNKNOWN"
)

critical_indicators = sum(
    1 for item in INDICATORS
    if item["severity"] == "critical"
)

severity_distribution = Counter(
    item["severity"]
    for item in INDICATORS
)

component_distribution = Counter(
    item["component"]
    for item in INDICATORS
)


# ============================================================
# OUTPUT
# ============================================================

print(
    "\n=== Day 27 Lab 11: AI IoC / IoB Extraction "
    "& Incident Severity Classification ==="
)


print("\n" + "=" * 80)
print("        EXTRACTED AI SECURITY INDICATORS")
print("=" * 80)

for indicator in INDICATORS:

    print(
        f"{indicator['indicator_id']} | "
        f"{indicator['indicator_type']} | "
        f"{indicator['name']} | "
        f"{indicator['severity'].upper()}"
    )

    print(
        f"  Component: {indicator['component']}"
    )

    print(
        f"  Value: {indicator['value']}"
    )


print("\n" + "=" * 80)
print("        INDICATOR SUMMARY")
print("=" * 80)

print(
    f"Total Indicators: {len(INDICATORS)}"
)

print(
    f"Indicators of Compromise: {ioc_count}"
)

print(
    f"Indicators of Behavior: {iob_count}"
)

print(
    f"Unknown Indicators: {unknown_count}"
)

print(
    f"Critical Indicators: {critical_indicators}"
)


print("\n=== Severity Distribution ===")

for severity, count in sorted(
    severity_distribution.items()
):
    print(
        f"{severity}: {count}"
    )


print("\n=== Component Distribution ===")

for component, count in sorted(
    component_distribution.items()
):
    print(
        f"{component}: {count}"
    )


print("\n" + "=" * 80)
print("        INCIDENT IMPACT FACTORS")
print("=" * 80)

for factor, active in IMPACT_FACTORS.items():

    print(
        f"{factor}: {active}"
    )


print("\n" + "=" * 80)
print("        INCIDENT SEVERITY CLASSIFICATION")
print("=" * 80)

print(
    f"Incident ID: {INCIDENT_ID}"
)

print(
    f"Trace ID: {TRACE_ID}"
)

print(
    f"Risk Score: {RISK_SCORE} / 100"
)

print(
    f"Incident Severity: {INCIDENT_SEVERITY}"
)

print(
    "Unauthorized Execution:",
    IMPACT_FACTORS[
        "unauthorized_execution"
    ],
)

print(
    "Unauthorized System Impact:",
    IMPACT_FACTORS[
        "unauthorized_system_impact"
    ],
)

print(
    "Cross-Session Propagation:",
    IMPACT_FACTORS[
        "cross_session_propagation"
    ],
)

print(
    "Persistent Memory Compromise:",
    IMPACT_FACTORS[
        "persistent_memory_compromise"
    ],
)


print("\n" + "=" * 80)
print("        INCIDENT BLAST RADIUS")
print("=" * 80)

print(
    "Affected Sessions:",
    BLAST_RADIUS[
        "sessions_affected"
    ],
)

print(
    "Affected Agents:",
    BLAST_RADIUS[
        "agents_affected"
    ],
)

print(
    "Affected Memory Stores:",
    BLAST_RADIUS[
        "memory_stores_affected"
    ],
)

print(
    "RAG Documents Involved:",
    BLAST_RADIUS[
        "rag_documents_involved"
    ],
)

print(
    "Restricted Targets:",
    BLAST_RADIUS[
        "restricted_targets_affected"
    ],
)

print(
    "Privileged Tools:",
    BLAST_RADIUS[
        "privileged_tools_involved"
    ],
)

print(
    "Cross-Session Impact:",
    BLAST_RADIUS["cross_session"],
)

print(
    "Unauthorized Impact:",
    BLAST_RADIUS[
        "unauthorized_impact"
    ],
)


print("\n" + "=" * 80)
print("        REUSABLE DETECTION INTELLIGENCE")
print("=" * 80)

for rule in DETECTION_INTELLIGENCE:

    print(
        f"{rule['rule_id']} | "
        f"{rule['priority'].upper()} | "
        f"{rule['name']}"
    )

    print(
        f"  Indicator: {rule['indicator']}"
    )


# ============================================================
# SECURITY CHECKS
# ============================================================

classification_complete = (
    unknown_count == 0
)

critical_incident_identified = (
    INCIDENT_SEVERITY == "CRITICAL"
)

unauthorized_impact_detected = (
    IMPACT_FACTORS[
        "unauthorized_system_impact"
    ]
)

cross_session_detected = (
    IMPACT_FACTORS[
        "cross_session_propagation"
    ]
)

persistent_compromise_detected = (
    IMPACT_FACTORS[
        "persistent_memory_compromise"
    ]
)

detection_intelligence_generated = (
    len(DETECTION_INTELLIGENCE) > 0
)


print("\n" + "=" * 80)
print("        INCIDENT INTELLIGENCE SECURITY CHECKS")
print("=" * 80)

print(
    "All Indicators Classified:",
    classification_complete,
)

print(
    "Critical Incident Identified:",
    critical_incident_identified,
)

print(
    "Unauthorized Impact Identified:",
    unauthorized_impact_detected,
)

print(
    "Cross-Session Propagation Identified:",
    cross_session_detected,
)

print(
    "Persistent Memory Compromise Identified:",
    persistent_compromise_detected,
)

print(
    "Reusable Detection Intelligence Generated:",
    detection_intelligence_generated,
)


# ============================================================
# EXPORT EVIDENCE
# ============================================================

REPORT = {
    "lab": "Day 27 Lab 11",
    "incident_id": INCIDENT_ID,
    "trace_id": TRACE_ID,
    "indicators": INDICATORS,
    "impact_factors": IMPACT_FACTORS,
    "risk_score": RISK_SCORE,
    "incident_severity": INCIDENT_SEVERITY,
    "blast_radius": BLAST_RADIUS,
    "detection_intelligence":
        DETECTION_INTELLIGENCE,
    "metrics": {
        "total_indicators":
            len(INDICATORS),
        "ioc_count":
            ioc_count,
        "iob_count":
            iob_count,
        "unknown_count":
            unknown_count,
        "critical_indicators":
            critical_indicators,
    },
    "security_checks": {
        "classification_complete":
            classification_complete,
        "critical_incident_identified":
            critical_incident_identified,
        "unauthorized_impact_detected":
            unauthorized_impact_detected,
        "cross_session_detected":
            cross_session_detected,
        "persistent_compromise_detected":
            persistent_compromise_detected,
        "detection_intelligence_generated":
            detection_intelligence_generated,
    },
}


OUTPUT_FILE = (
    "day27-ai-ioc-iob-severity-evidence.json"
)

with open(
    OUTPUT_FILE,
    "w",
    encoding="utf-8",
) as file:

    json.dump(
        REPORT,
        file,
        indent=2,
    )


print("\nEvidence written to:")
print(OUTPUT_FILE)


print("\nSecurity Interpretation:")

print(
    "The forensic evidence has been converted into "
    "reusable AI security indicators covering prompt "
    "manipulation, poisoned retrieval, persistent memory "
    "compromise, cross-session influence, privileged tool "
    "selection, authorization bypass, unauthorized execution, "
    "and system impact."
)

print(
    "Indicators of Compromise describe observable compromised "
    "artifacts or state, while Indicators of Behavior describe "
    "security-relevant actions and attack-chain behavior."
)

print(
    "Severity classification combines persistence, propagation, "
    "privileged execution, authorization bypass, and actual "
    "system impact so that incident response priority is based "
    "on consequence rather than a single suspicious prompt."
)

print("\nCore Principle:")

print(
    "If an AI security event cannot be observed and reconstructed, "
    "it cannot be reliably investigated or improved."
)