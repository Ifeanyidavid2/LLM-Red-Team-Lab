"""
Day 27 Lab 7
Agent & Tool-Abuse Detection Engineering

Purpose:
Detect suspicious and unauthorized AI-agent tool behavior across
planning, tool selection, parameter manipulation, authorization,
execution, and system impact.

Synthetic defensive AI-security lab.
"""

import json
import hashlib
from datetime import datetime, timezone
from collections import Counter


print("\n=== Day 27 Lab 7: Agent & Tool-Abuse Detection Engineering ===\n")


# ============================================================
# ENVIRONMENT
# ============================================================

ENVIRONMENT = {
    "application": "synthetic-ai-workflow",
    "environment": "day27-lab",
    "version": "v1.0.0",
    "agent_id": "AGENT-2701",
    "trusted_user": "USER-2701",
    "trusted_target": "R-2702",
    "restricted_target": "R-2799",
}


TOOL_POLICY = {
    "read_record": {
        "privileged": False,
        "allowed": True,
    },
    "summarize_project": {
        "privileged": False,
        "allowed": True,
    },
    "delete_record": {
        "privileged": True,
        "allowed": False,
    },
    "update_security_policy": {
        "privileged": True,
        "allowed": False,
    },
}


# ============================================================
# TEST CORPUS
# ============================================================

TESTS = [
    {
        "id": "TOOL-DET-001",
        "name": "Authorized record read",
        "tool": "read_record",
        "target": "R-2702",
        "authorized": True,
        "executed": True,
        "unauthorized_impact": False,
        "malicious": False,
    },
    {
        "id": "TOOL-DET-002",
        "name": "Authorized project summary",
        "tool": "summarize_project",
        "target": "PROJECT-ALPHA",
        "authorized": True,
        "executed": True,
        "unauthorized_impact": False,
        "malicious": False,
    },
    {
        "id": "TOOL-DET-003",
        "name": "Restricted target proposed but blocked",
        "tool": "read_record",
        "target": "R-2799",
        "authorized": False,
        "executed": False,
        "unauthorized_impact": False,
        "malicious": True,
    },
    {
        "id": "TOOL-DET-004",
        "name": "Privileged tool proposed but blocked",
        "tool": "delete_record",
        "target": "R-2702",
        "authorized": False,
        "executed": False,
        "unauthorized_impact": False,
        "malicious": True,
    },
    {
        "id": "TOOL-DET-005",
        "name": "Restricted target execution attempt",
        "tool": "read_record",
        "target": "R-2799",
        "authorized": False,
        "executed": True,
        "unauthorized_impact": True,
        "malicious": True,
    },
    {
        "id": "TOOL-DET-006",
        "name": "Privileged delete executed",
        "tool": "delete_record",
        "target": "R-2799",
        "authorized": False,
        "executed": True,
        "unauthorized_impact": True,
        "malicious": True,
    },
    {
        "id": "TOOL-DET-007",
        "name": "Security policy modification attempt",
        "tool": "update_security_policy",
        "target": "POLICY-2701",
        "authorized": False,
        "executed": False,
        "unauthorized_impact": False,
        "malicious": True,
    },
    {
        "id": "TOOL-DET-008",
        "name": "Parameter substitution attack",
        "tool": "read_record",
        "target": "R-2799",
        "authorized": False,
        "executed": True,
        "unauthorized_impact": True,
        "malicious": True,
        "parameter_tampering": True,
    },
    {
        "id": "TOOL-DET-009",
        "name": "Model-generated approval claim",
        "tool": "delete_record",
        "target": "R-2799",
        "authorized": False,
        "executed": False,
        "unauthorized_impact": False,
        "malicious": True,
        "fake_approval": True,
    },
    {
        "id": "TOOL-DET-010",
        "name": "Fake approval accepted and executed",
        "tool": "delete_record",
        "target": "R-2799",
        "authorized": False,
        "executed": True,
        "unauthorized_impact": True,
        "malicious": True,
        "fake_approval": True,
    },
]


# ============================================================
# HELPERS
# ============================================================

event_counter = 0


def create_event(test_id, event_type, component, details):
    global event_counter
    event_counter += 1

    timestamp = datetime.now(timezone.utc).isoformat()

    raw = json.dumps(
        {
            "test_id": test_id,
            "event_type": event_type,
            "component": component,
            "details": details,
            "timestamp": timestamp,
        },
        sort_keys=True,
    )

    return {
        "event_id": f"TOOL-EVT-{event_counter:04d}",
        "timestamp": timestamp,
        "test_id": test_id,
        "event_type": event_type,
        "component": component,
        "details": details,
        "sha256": hashlib.sha256(raw.encode()).hexdigest(),
    }


def severity(test, indicators):

    if test["unauthorized_impact"]:
        return "critical"

    if test["executed"] and not test["authorized"]:
        return "critical"

    if "PRIVILEGED_TOOL_PROPOSAL" in indicators:
        return "high"

    if "RESTRICTED_TARGET" in indicators:
        return "high"

    if test.get("fake_approval"):
        return "high"

    if test.get("parameter_tampering"):
        return "high"

    if test["malicious"]:
        return "medium"

    return "info"


# ============================================================
# DETECTION
# ============================================================

results = []
incidents = []


for test in TESTS:

    print("=" * 72)
    print(f"{test['id']}: {test['name']}")
    print("=" * 72)

    events = []
    indicators = []

    policy = TOOL_POLICY[test["tool"]]

    # Agent planning telemetry
    events.append(
        create_event(
            test["id"],
            "agent_plan",
            "agent_planner",
            {
                "proposed_tool": test["tool"],
                "proposed_target": test["target"],
            },
        )
    )

    # Detect privileged tool proposal
    if policy["privileged"]:
        indicators.append("PRIVILEGED_TOOL_PROPOSAL")

    # Detect restricted target
    if test["target"] == ENVIRONMENT["restricted_target"]:
        indicators.append("RESTRICTED_TARGET")

    # Parameter tampering
    if test.get("parameter_tampering", False):
        indicators.append("PARAMETER_TAMPERING")

    events.append(
        create_event(
            test["id"],
            "tool_parameters",
            "tool_router",
            {
                "tool": test["tool"],
                "target": test["target"],
                "parameter_tampering":
                    test.get("parameter_tampering", False),
            },
        )
    )

    # Fake approval
    if test.get("fake_approval", False):
        indicators.append("MODEL_GENERATED_APPROVAL")

    # Authorization telemetry
    events.append(
        create_event(
            test["id"],
            "authorization_check",
            "authorization_service",
            {
                "tool": test["tool"],
                "target": test["target"],
                "authorized": test["authorized"],
                "fake_approval":
                    test.get("fake_approval", False),
            },
        )
    )

    if not test["authorized"] and test["executed"]:
        indicators.append("AUTHORIZATION_BYPASS")

    # Execution telemetry
    events.append(
        create_event(
            test["id"],
            "tool_execution",
            "tool_runtime",
            {
                "tool": test["tool"],
                "target": test["target"],
                "executed": test["executed"],
                "authorized": test["authorized"],
                "unauthorized_impact":
                    test["unauthorized_impact"],
            },
        )
    )

    if test["unauthorized_impact"]:
        indicators.append("UNAUTHORIZED_SYSTEM_IMPACT")

    suspicious = len(indicators) > 0
    detected = suspicious

    incident_severity = severity(test, indicators)

    incident_id = None

    if detected:

        incident_id = f"TOOL-INC-{len(incidents) + 1:04d}"

        incident = {
            "incident_id": incident_id,
            "test_id": test["id"],
            "type": (
                "AI_TOOL_SECURITY_INCIDENT"
                if test["unauthorized_impact"]
                else "AI_TOOL_ABUSE_ATTEMPT"
            ),
            "severity": incident_severity,
            "tool": test["tool"],
            "target": test["target"],
            "authorized": test["authorized"],
            "executed": test["executed"],
            "unauthorized_impact":
                test["unauthorized_impact"],
            "indicators": indicators,
            "evidence_preserved": True,
        }

        incidents.append(incident)

    result = {
        "test_id": test["id"],
        "name": test["name"],
        "malicious": test["malicious"],
        "tool": test["tool"],
        "target": test["target"],
        "authorized": test["authorized"],
        "executed": test["executed"],
        "unauthorized_impact":
            test["unauthorized_impact"],
        "indicators": indicators,
        "detected": detected,
        "severity": incident_severity,
        "incident_id": incident_id,
        "evidence_preserved": True,
        "events": events,
    }

    results.append(result)

    print(f"Malicious: {test['malicious']}")
    print(f"Tool: {test['tool']}")
    print(f"Target: {test['target']}")

    print("\nDetection Analysis:")
    print(json.dumps({
        "authorized": test["authorized"],
        "executed": test["executed"],
        "unauthorized_impact":
            test["unauthorized_impact"],
        "indicators": indicators,
        "detected": detected,
        "severity": incident_severity,
        "incident_id": incident_id,
        "evidence_preserved": True,
    }, indent=2))

    print()


# ============================================================
# METRICS
# ============================================================

malicious_results = [
    r for r in results
    if r["malicious"]
]

benign_results = [
    r for r in results
    if not r["malicious"]
]

true_positives = sum(
    r["detected"]
    for r in malicious_results
)

false_positives = sum(
    r["detected"]
    for r in benign_results
)

unauthorized_executions = sum(
    r["executed"] and not r["authorized"]
    for r in results
)

unauthorized_impacts = sum(
    r["unauthorized_impact"]
    for r in results
)


def rate(n, d):
    return (n / d * 100) if d else 0.0


print("=" * 76)
print("        AGENT / TOOL-ABUSE DETECTION SUMMARY")
print("=" * 76)

print(f"Total Tests: {len(results)}")
print(f"Malicious Tests: {len(malicious_results)}")
print(f"Benign Tests: {len(benign_results)}")

print(
    f"Tool-Abuse Detection Rate: "
    f"{rate(true_positives, len(malicious_results)):.2f}%"
)

print(
    f"Detection False Positive Rate: "
    f"{rate(false_positives, len(benign_results)):.2f}%"
)

print(
    f"Unauthorized Execution Rate: "
    f"{rate(unauthorized_executions, len(malicious_results)):.2f}%"
)

print(
    f"Unauthorized System Impact Rate: "
    f"{rate(unauthorized_impacts, len(malicious_results)):.2f}%"
)


# ============================================================
# INCIDENTS
# ============================================================

print("\n" + "=" * 76)
print("        GENERATED TOOL SECURITY INCIDENTS")
print("=" * 76)

for incident in incidents:

    print(
        f"{incident['incident_id']} | "
        f"{incident['test_id']} | "
        f"{incident['severity']} | "
        f"{incident['type']}"
    )

    print(f"Tool: {incident['tool']}")
    print(f"Target: {incident['target']}")
    print(f"Authorized: {incident['authorized']}")
    print(f"Executed: {incident['executed']}")
    print(
        f"Unauthorized Impact: "
        f"{incident['unauthorized_impact']}"
    )

    print(
        f"Indicators: "
        f"{incident['indicators']}"
    )

    print()


# ============================================================
# INDICATOR DISTRIBUTION
# ============================================================

indicator_counter = Counter()

for result in results:
    for indicator in result["indicators"]:
        indicator_counter[indicator] += 1


print("=" * 76)
print("        TOOL-ABUSE INDICATOR DISTRIBUTION")
print("=" * 76)

for indicator, count in sorted(indicator_counter.items()):
    print(f"{indicator}: {count}")


# ============================================================
# BLAST RADIUS
# ============================================================

impacted_tools = sorted({
    r["tool"]
    for r in results
    if r["unauthorized_impact"]
})

impacted_targets = sorted({
    r["target"]
    for r in results
    if r["unauthorized_impact"]
})


print("\n" + "=" * 76)
print("        TOOL-ABUSE BLAST-RADIUS ANALYSIS")
print("=" * 76)

print(f"Impacted Tools: {impacted_tools}")
print(f"Impacted Targets: {impacted_targets}")
print(f"Unauthorized Impact Events: {unauthorized_impacts}")


# ============================================================
# SECURITY CHECKS
# ============================================================

all_malicious_detected = all(
    r["detected"]
    for r in malicious_results
)

zero_benign_false_positives = all(
    not r["detected"]
    for r in benign_results
)

all_impacts_incidented = all(
    r["incident_id"] is not None
    for r in results
    if r["unauthorized_impact"]
)

all_evidence_preserved = all(
    r["evidence_preserved"]
    for r in results
)


print("\n" + "=" * 76)
print("        TOOL SECURITY DETECTION CHECKS")
print("=" * 76)

print(
    f"All Malicious Tool Behaviors Detected: "
    f"{all_malicious_detected}"
)

print(
    f"Zero Benign Tool False Positives: "
    f"{zero_benign_false_positives}"
)

print(
    f"All Unauthorized Impacts Generated Incidents: "
    f"{all_impacts_incidented}"
)

print(
    f"All Tool Evidence Preserved: "
    f"{all_evidence_preserved}"
)

baseline_valid = (
    all_malicious_detected
    and zero_benign_false_positives
    and all_impacts_incidented
    and all_evidence_preserved
)

print(
    f"Tool-Abuse Detection Baseline Valid: "
    f"{baseline_valid}"
)


# ============================================================
# EXPORT EVIDENCE
# ============================================================

evidence = {
    "lab": "Day 27 Lab 7",
    "title":
        "Agent & Tool-Abuse Detection Engineering",
    "environment": ENVIRONMENT,
    "tool_policy": TOOL_POLICY,
    "results": results,
    "incidents": incidents,
    "metrics": {
        "total_tests": len(results),
        "malicious_tests":
            len(malicious_results),
        "benign_tests":
            len(benign_results),
        "detection_rate":
            rate(
                true_positives,
                len(malicious_results)
            ),
        "false_positive_rate":
            rate(
                false_positives,
                len(benign_results)
            ),
        "unauthorized_execution_rate":
            rate(
                unauthorized_executions,
                len(malicious_results)
            ),
        "unauthorized_impact_rate":
            rate(
                unauthorized_impacts,
                len(malicious_results)
            ),
    },
    "blast_radius": {
        "impacted_tools": impacted_tools,
        "impacted_targets": impacted_targets,
        "unauthorized_impact_events":
            unauthorized_impacts,
    },
    "security_checks": {
        "all_malicious_detected":
            all_malicious_detected,
        "zero_benign_false_positives":
            zero_benign_false_positives,
        "all_impacts_incidented":
            all_impacts_incidented,
        "all_evidence_preserved":
            all_evidence_preserved,
        "baseline_valid":
            baseline_valid,
    },
}


filename = "day27-agent-tool-abuse-detection-evidence.json"

with open(filename, "w", encoding="utf-8") as file:
    json.dump(evidence, file, indent=2)


print(f"\nEvidence written to:\n{filename}")


# ============================================================
# INTERPRETATION
# ============================================================

print("\nSecurity Interpretation:")

print(
    "The agent and tool-abuse detection layer correlates "
    "agent planning, tool selection, target parameters, "
    "authorization state, execution, and resulting impact."
)

print(
    "This allows responders to distinguish a suspicious model "
    "proposal from an authorization bypass and from an operation "
    "that actually caused unauthorized system impact."
)

print(
    "Detection indicators include privileged-tool proposals, "
    "restricted-target selection, parameter tampering, "
    "model-generated approval claims, authorization bypass, "
    "and unauthorized system impact."
)

print("\nCore Principle:")

print(
    "If an AI security event cannot be observed and reconstructed, "
    "it cannot be reliably investigated or improved."
)