"""
Day 27 Lab 12
Blast-Radius Analysis & Affected-Asset Scoping

Purpose:
Determine the confirmed and potential scope of a synthetic AI
security incident across sessions, agents, memory, RAG, tools,
targets, identities, and downstream components.

Core Principle:
If an AI security event cannot be observed and reconstructed,
it cannot be reliably investigated or improved.
"""

import json
from collections import Counter


INCIDENT_ID = "INC-2712"
TRACE_ID = "TRACE-2712"


# ============================================================
# INCIDENT EVIDENCE
# ============================================================

INCIDENT_EVENTS = [
    {
        "event_id": "EVT-2712-001",
        "session": "SESSION-2701",
        "agent": "AGENT-2701",
        "component": "input_gateway",
        "event": "prompt_injection",
        "asset": "SESSION-2701",
        "impact": "confirmed",
    },
    {
        "event_id": "EVT-2712-002",
        "session": "SESSION-2701",
        "agent": "AGENT-2701",
        "component": "retrieval_service",
        "event": "poisoned_rag_retrieval",
        "asset": "DOC-2791",
        "impact": "confirmed",
    },
    {
        "event_id": "EVT-2712-003",
        "session": "SESSION-2701",
        "agent": "AGENT-2701",
        "component": "context_security_gateway",
        "event": "poisoned_context_admission",
        "asset": "CONTEXT-2701",
        "impact": "confirmed",
    },
    {
        "event_id": "EVT-2712-004",
        "session": "SESSION-2701",
        "agent": "AGENT-2701",
        "component": "memory_service",
        "event": "unauthorized_memory_write",
        "asset": "MEMORY-2701",
        "impact": "confirmed",
    },
    {
        "event_id": "EVT-2712-005",
        "session": "SESSION-2702",
        "agent": "AGENT-2702",
        "component": "memory_service",
        "event": "cross_session_memory_read",
        "asset": "SESSION-2702",
        "impact": "confirmed",
    },
    {
        "event_id": "EVT-2712-006",
        "session": "SESSION-2702",
        "agent": "AGENT-2702",
        "component": "agent_planner",
        "event": "manipulated_agent_plan",
        "asset": "AGENT-2702",
        "impact": "confirmed",
    },
    {
        "event_id": "EVT-2712-007",
        "session": "SESSION-2702",
        "agent": "AGENT-2702",
        "component": "tool_router",
        "event": "restricted_target_selection",
        "asset": "R-2799",
        "impact": "confirmed",
    },
    {
        "event_id": "EVT-2712-008",
        "session": "SESSION-2702",
        "agent": "AGENT-2702",
        "component": "tool_router",
        "event": "privileged_tool_selection",
        "asset": "delete_record",
        "impact": "confirmed",
    },
    {
        "event_id": "EVT-2712-009",
        "session": "SESSION-2702",
        "agent": "AGENT-2702",
        "component": "authorization_service",
        "event": "authorization_bypass",
        "asset": "AUTHZ-2701",
        "impact": "confirmed",
    },
    {
        "event_id": "EVT-2712-010",
        "session": "SESSION-2702",
        "agent": "AGENT-2702",
        "component": "record_service",
        "event": "unauthorized_record_deletion",
        "asset": "R-2799",
        "impact": "confirmed",
    },
]


# ============================================================
# ASSET INVENTORY
# ============================================================

ASSET_INVENTORY = [
    {
        "asset_id": "SESSION-2701",
        "asset_type": "session",
        "criticality": "medium",
    },
    {
        "asset_id": "SESSION-2702",
        "asset_type": "session",
        "criticality": "high",
    },
    {
        "asset_id": "SESSION-2703",
        "asset_type": "session",
        "criticality": "medium",
    },
    {
        "asset_id": "AGENT-2701",
        "asset_type": "agent",
        "criticality": "high",
    },
    {
        "asset_id": "AGENT-2702",
        "asset_type": "agent",
        "criticality": "critical",
    },
    {
        "asset_id": "MEMORY-2701",
        "asset_type": "memory_store",
        "criticality": "critical",
    },
    {
        "asset_id": "MEMORY-2702",
        "asset_type": "memory_store",
        "criticality": "high",
    },
    {
        "asset_id": "DOC-2791",
        "asset_type": "rag_document",
        "criticality": "high",
    },
    {
        "asset_id": "RAG-2701",
        "asset_type": "rag_store",
        "criticality": "high",
    },
    {
        "asset_id": "CONTEXT-2701",
        "asset_type": "runtime_context",
        "criticality": "high",
    },
    {
        "asset_id": "R-2799",
        "asset_type": "restricted_target",
        "criticality": "critical",
    },
    {
        "asset_id": "delete_record",
        "asset_type": "privileged_tool",
        "criticality": "critical",
    },
    {
        "asset_id": "AUTHZ-2701",
        "asset_type": "authorization_boundary",
        "criticality": "critical",
    },
    {
        "asset_id": "USER-2701",
        "asset_type": "identity",
        "criticality": "high",
    },
    {
        "asset_id": "RECORD-SERVICE-2701",
        "asset_type": "downstream_service",
        "criticality": "critical",
    },
]


# ============================================================
# CONFIRMED COMPROMISE
# ============================================================

confirmed_asset_ids = {
    event["asset"]
    for event in INCIDENT_EVENTS
    if event["impact"] == "confirmed"
}

# Agent 2701 participated in the compromised first session.
confirmed_asset_ids.add("AGENT-2701")


# ============================================================
# POTENTIAL EXPOSURE
# ============================================================

# These assets are not proven compromised but have a reasonable
# relationship to the affected trust path and must be scoped.

POTENTIALLY_EXPOSED = {
    "SESSION-2703": (
        "Potential future session could consume persistent "
        "compromised memory."
    ),
    "MEMORY-2702": (
        "Adjacent memory store requires review for propagation "
        "or shared-write exposure."
    ),
    "RAG-2701": (
        "RAG store contained or delivered the poisoned document."
    ),
    "USER-2701": (
        "Identity activity must be reviewed to distinguish "
        "attacker-controlled behavior from compromised workflow."
    ),
    "RECORD-SERVICE-2701": (
        "Downstream record service processed the unauthorized "
        "privileged operation."
    ),
}


# ============================================================
# BUILD SCOPED ASSET RECORDS
# ============================================================

SCOPED_ASSETS = []

for asset in ASSET_INVENTORY:

    asset_id = asset["asset_id"]

    if asset_id in confirmed_asset_ids:
        status = "CONFIRMED_COMPROMISED"
        reason = (
            "Direct evidence links this asset to the "
            "reconstructed attack chain."
        )

    elif asset_id in POTENTIALLY_EXPOSED:
        status = "POTENTIALLY_EXPOSED"
        reason = POTENTIALLY_EXPOSED[asset_id]

    else:
        status = "NO_CURRENT_EVIDENCE"
        reason = (
            "No current incident evidence demonstrates "
            "compromise or exposure."
        )

    SCOPED_ASSETS.append({
        **asset,
        "scope_status": status,
        "scope_reason": reason,
    })


# ============================================================
# SPREAD ANALYSIS
# ============================================================

affected_sessions = sorted({
    event["session"]
    for event in INCIDENT_EVENTS
})

affected_agents = sorted({
    event["agent"]
    for event in INCIDENT_EVENTS
})

affected_components = sorted({
    event["component"]
    for event in INCIDENT_EVENTS
})

cross_session_spread = (
    len(affected_sessions) > 1
)

cross_agent_spread = (
    len(affected_agents) > 1
)

persistent_compromise = (
    "MEMORY-2701" in confirmed_asset_ids
)

privileged_execution_scope = (
    "delete_record" in confirmed_asset_ids
)

restricted_target_impact = (
    "R-2799" in confirmed_asset_ids
)

authorization_boundary_affected = (
    "AUTHZ-2701" in confirmed_asset_ids
)


# ============================================================
# CONTAINMENT SCOPE
# ============================================================

CONTAINMENT_ACTIONS = []

for asset in SCOPED_ASSETS:

    if asset["scope_status"] == "CONFIRMED_COMPROMISED":

        CONTAINMENT_ACTIONS.append({
            "asset_id": asset["asset_id"],
            "asset_type": asset["asset_type"],
            "priority": (
                "IMMEDIATE"
                if asset["criticality"] == "critical"
                else "HIGH"
            ),
            "action":
                "isolate_preserve_and_validate",
        })

    elif asset["scope_status"] == "POTENTIALLY_EXPOSED":

        CONTAINMENT_ACTIONS.append({
            "asset_id": asset["asset_id"],
            "asset_type": asset["asset_type"],
            "priority": "REVIEW",
            "action":
                "investigate_and_restrict_if_required",
        })


# ============================================================
# METRICS
# ============================================================

total_assets = len(SCOPED_ASSETS)

confirmed_count = sum(
    1 for asset in SCOPED_ASSETS
    if asset["scope_status"]
    == "CONFIRMED_COMPROMISED"
)

potential_count = sum(
    1 for asset in SCOPED_ASSETS
    if asset["scope_status"]
    == "POTENTIALLY_EXPOSED"
)

unaffected_count = sum(
    1 for asset in SCOPED_ASSETS
    if asset["scope_status"]
    == "NO_CURRENT_EVIDENCE"
)

assets_requiring_action = (
    confirmed_count + potential_count
)

blast_radius_rate = (
    assets_requiring_action
    / total_assets
    * 100
)

confirmed_compromise_rate = (
    confirmed_count
    / total_assets
    * 100
)

scope_status_distribution = Counter(
    asset["scope_status"]
    for asset in SCOPED_ASSETS
)

asset_type_distribution = Counter(
    asset["asset_type"]
    for asset in SCOPED_ASSETS
    if asset["scope_status"]
    != "NO_CURRENT_EVIDENCE"
)


# ============================================================
# SCOPING COMPLETENESS
# ============================================================

REQUIRED_SCOPE_TYPES = {
    "session",
    "agent",
    "memory_store",
    "rag_document",
    "rag_store",
    "runtime_context",
    "restricted_target",
    "privileged_tool",
    "authorization_boundary",
    "identity",
    "downstream_service",
}

observed_scope_types = {
    asset["asset_type"]
    for asset in SCOPED_ASSETS
    if asset["scope_status"]
    != "NO_CURRENT_EVIDENCE"
}

missing_scope_types = sorted(
    REQUIRED_SCOPE_TYPES
    - observed_scope_types
)

scoping_completeness_rate = (
    (
        len(REQUIRED_SCOPE_TYPES)
        - len(missing_scope_types)
    )
    / len(REQUIRED_SCOPE_TYPES)
    * 100
)


# ============================================================
# OUTPUT
# ============================================================

print(
    "\n=== Day 27 Lab 12: Blast-Radius Analysis "
    "& Affected-Asset Scoping ==="
)


print("\n" + "=" * 82)
print("        AFFECTED-ASSET SCOPING")
print("=" * 82)

for asset in SCOPED_ASSETS:

    print(
        f"{asset['asset_id']} | "
        f"{asset['asset_type']} | "
        f"{asset['criticality'].upper()} | "
        f"{asset['scope_status']}"
    )

    print(
        f"  Reason: {asset['scope_reason']}"
    )


print("\n" + "=" * 82)
print("        BLAST-RADIUS SUMMARY")
print("=" * 82)

print(f"Total Inventoried Assets: {total_assets}")
print(f"Confirmed Compromised Assets: {confirmed_count}")
print(f"Potentially Exposed Assets: {potential_count}")
print(f"No-Current-Evidence Assets: {unaffected_count}")
print(f"Assets Requiring Response Action: {assets_requiring_action}")

print(
    f"Confirmed Compromise Rate: "
    f"{confirmed_compromise_rate:.2f}%"
)

print(
    f"Overall Blast-Radius Scope Rate: "
    f"{blast_radius_rate:.2f}%"
)


print("\n=== Scope Status Distribution ===")

for status, count in sorted(
    scope_status_distribution.items()
):
    print(f"{status}: {count}")


print("\n=== Affected Asset Types ===")

for asset_type, count in sorted(
    asset_type_distribution.items()
):
    print(f"{asset_type}: {count}")


print("\n" + "=" * 82)
print("        PROPAGATION ANALYSIS")
print("=" * 82)

print(
    "Affected Sessions:",
    affected_sessions,
)

print(
    "Affected Session Count:",
    len(affected_sessions),
)

print(
    "Affected Agents:",
    affected_agents,
)

print(
    "Affected Agent Count:",
    len(affected_agents),
)

print(
    "Affected Components:",
    affected_components,
)

print(
    "Affected Component Count:",
    len(affected_components),
)

print(
    "Cross-Session Spread:",
    cross_session_spread,
)

print(
    "Cross-Agent Spread:",
    cross_agent_spread,
)

print(
    "Persistent Memory Compromise:",
    persistent_compromise,
)

print(
    "Privileged Execution Scope:",
    privileged_execution_scope,
)

print(
    "Restricted Target Impact:",
    restricted_target_impact,
)

print(
    "Authorization Boundary Affected:",
    authorization_boundary_affected,
)


print("\n" + "=" * 82)
print("        REQUIRED CONTAINMENT SCOPE")
print("=" * 82)

for action in CONTAINMENT_ACTIONS:

    print(
        f"{action['asset_id']} | "
        f"{action['asset_type']} | "
        f"{action['priority']} | "
        f"{action['action']}"
    )


print("\n" + "=" * 82)
print("        SCOPING COMPLETENESS")
print("=" * 82)

print(
    f"Required Scope Categories: "
    f"{len(REQUIRED_SCOPE_TYPES)}"
)

print(
    f"Observed Scope Categories: "
    f"{len(observed_scope_types)}"
)

print(
    "Missing Scope Categories:",
    missing_scope_types,
)

print(
    f"Scoping Completeness Rate: "
    f"{scoping_completeness_rate:.2f}%"
)


# ============================================================
# SECURITY CHECKS
# ============================================================

all_scope_categories_covered = (
    len(missing_scope_types) == 0
)

confirmed_compromise_identified = (
    confirmed_count > 0
)

potential_exposure_identified = (
    potential_count > 0
)

containment_scope_generated = (
    len(CONTAINMENT_ACTIONS) > 0
)

blast_radius_reconstructed = all([
    cross_session_spread,
    cross_agent_spread,
    persistent_compromise,
    privileged_execution_scope,
    restricted_target_impact,
    authorization_boundary_affected,
])


print("\n" + "=" * 82)
print("        BLAST-RADIUS SECURITY CHECKS")
print("=" * 82)

print(
    "Confirmed Compromise Identified:",
    confirmed_compromise_identified,
)

print(
    "Potential Exposure Identified:",
    potential_exposure_identified,
)

print(
    "Cross-Session Spread Identified:",
    cross_session_spread,
)

print(
    "Cross-Agent Spread Identified:",
    cross_agent_spread,
)

print(
    "Persistent Compromise Identified:",
    persistent_compromise,
)

print(
    "Privileged Execution Scope Identified:",
    privileged_execution_scope,
)

print(
    "Authorization Boundary Impact Identified:",
    authorization_boundary_affected,
)

print(
    "All Scope Categories Covered:",
    all_scope_categories_covered,
)

print(
    "Containment Scope Generated:",
    containment_scope_generated,
)

print(
    "Blast Radius Reconstructed:",
    blast_radius_reconstructed,
)


# ============================================================
# EXPORT
# ============================================================

REPORT = {
    "lab": "Day 27 Lab 12",
    "incident_id": INCIDENT_ID,
    "trace_id": TRACE_ID,
    "scoped_assets": SCOPED_ASSETS,
    "affected_sessions": affected_sessions,
    "affected_agents": affected_agents,
    "affected_components": affected_components,
    "containment_actions": CONTAINMENT_ACTIONS,
    "metrics": {
        "total_assets": total_assets,
        "confirmed_compromised_assets":
            confirmed_count,
        "potentially_exposed_assets":
            potential_count,
        "no_current_evidence_assets":
            unaffected_count,
        "assets_requiring_action":
            assets_requiring_action,
        "confirmed_compromise_rate":
            confirmed_compromise_rate,
        "blast_radius_scope_rate":
            blast_radius_rate,
        "scoping_completeness_rate":
            scoping_completeness_rate,
    },
    "propagation": {
        "cross_session_spread":
            cross_session_spread,
        "cross_agent_spread":
            cross_agent_spread,
        "persistent_memory_compromise":
            persistent_compromise,
        "privileged_execution_scope":
            privileged_execution_scope,
        "restricted_target_impact":
            restricted_target_impact,
        "authorization_boundary_affected":
            authorization_boundary_affected,
    },
    "security_checks": {
        "confirmed_compromise_identified":
            confirmed_compromise_identified,
        "potential_exposure_identified":
            potential_exposure_identified,
        "all_scope_categories_covered":
            all_scope_categories_covered,
        "containment_scope_generated":
            containment_scope_generated,
        "blast_radius_reconstructed":
            blast_radius_reconstructed,
    },
}


OUTPUT_FILE = (
    "day27-blast-radius-affected-asset-evidence.json"
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
    "Blast-radius analysis distinguishes assets directly "
    "confirmed in the reconstructed attack chain from assets "
    "that are potentially exposed because they share memory, "
    "retrieval, identity, authorization, or downstream "
    "execution relationships."
)

print(
    "The incident crossed session and agent boundaries, "
    "persisted through memory, reached a privileged tool, "
    "affected an authorization boundary, and produced impact "
    "against a restricted target."
)

print(
    "Containment must therefore address the complete affected "
    "trust path rather than only the session in which the "
    "unauthorized execution was observed."
)

print("\nCore Principle:")

print(
    "If an AI security event cannot be observed and reconstructed, "
    "it cannot be reliably investigated or improved."
)