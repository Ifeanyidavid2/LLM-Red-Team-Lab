"""
Day 27 Lab 13
AI Incident Containment & Eradication Controls

Purpose:
Simulate containment and eradication of a synthetic AI incident
after blast-radius analysis has identified compromised sessions,
agents, memory, RAG content, privileged tools, authorization
boundaries, and downstream resources.

Core Principle:
If an AI security event cannot be observed and reconstructed,
it cannot be reliably investigated or improved.
"""

import json


INCIDENT_ID = "INC-2713"
TRACE_ID = "TRACE-2713"


# ============================================================
# PRE-CONTAINMENT COMPROMISED STATE
# ============================================================

SYSTEM_STATE = {
    "sessions": {
        "SESSION-2701": {
            "active": True,
            "compromised": True,
        },
        "SESSION-2702": {
            "active": True,
            "compromised": True,
        },
        "SESSION-2703": {
            "active": True,
            "compromised": False,
            "potentially_exposed": True,
        },
    },

    "agents": {
        "AGENT-2701": {
            "enabled": True,
            "compromised": True,
        },
        "AGENT-2702": {
            "enabled": True,
            "compromised": True,
        },
    },

    "memory": {
        "MEMORY-2701": {
            "enabled": True,
            "compromised": True,
            "malicious_state_present": True,
        },
        "MEMORY-2702": {
            "enabled": True,
            "compromised": False,
            "potentially_exposed": True,
        },
    },

    "rag": {
        "DOC-2791": {
            "available": True,
            "trusted": False,
            "poisoned": True,
        },
        "RAG-2701": {
            "enabled": True,
            "potentially_exposed": True,
        },
    },

    "tools": {
        "delete_record": {
            "enabled": True,
            "privileged": True,
            "incident_involved": True,
        },
        "read_record": {
            "enabled": True,
            "privileged": False,
            "incident_involved": False,
        },
    },

    "authorization": {
        "AUTHZ-2701": {
            "trusted": False,
            "bypass_observed": True,
        }
    },

    "targets": {
        "R-2799": {
            "restricted": True,
            "affected": True,
            "access_blocked": False,
        }
    },

    "identity": {
        "USER-2701": {
            "enabled": True,
            "under_review": True,
        }
    },

    "downstream_services": {
        "RECORD-SERVICE-2701": {
            "enabled": True,
            "under_review": True,
        }
    },
}


# ============================================================
# FORENSIC PRESERVATION
# ============================================================

FORENSIC_PRESERVATION = {
    "prompt_evidence_preserved": True,
    "rag_evidence_preserved": True,
    "memory_snapshot_preserved": True,
    "agent_plan_preserved": True,
    "authorization_logs_preserved": True,
    "tool_execution_logs_preserved": True,
    "impact_evidence_preserved": True,
    "chain_of_custody_preserved": True,
}


# ============================================================
# CONTAINMENT ACTION ENGINE
# ============================================================

ACTIONS = []


def record_action(
    action_id,
    asset,
    action,
    result,
    reason,
):

    ACTIONS.append({
        "action_id": action_id,
        "asset": asset,
        "action": action,
        "result": result,
        "reason": reason,
    })


# 1. Terminate compromised sessions

for session_id in [
    "SESSION-2701",
    "SESSION-2702",
]:

    SYSTEM_STATE["sessions"][session_id]["active"] = False

    record_action(
        f"ACT-{len(ACTIONS)+1:04d}",
        session_id,
        "terminate_session",
        "SUCCESS",
        "Compromised session removed from active execution.",
    )


# 2. Restrict potentially exposed session

SYSTEM_STATE["sessions"]["SESSION-2703"]["active"] = False

record_action(
    f"ACT-{len(ACTIONS)+1:04d}",
    "SESSION-2703",
    "temporarily_restrict_session",
    "SUCCESS",
    "Potentially exposed session restricted pending validation.",
)


# 3. Disable compromised agents

for agent_id in [
    "AGENT-2701",
    "AGENT-2702",
]:

    SYSTEM_STATE["agents"][agent_id]["enabled"] = False

    record_action(
        f"ACT-{len(ACTIONS)+1:04d}",
        agent_id,
        "disable_agent",
        "SUCCESS",
        "Compromised agent prevented from generating new actions.",
    )


# 4. Quarantine compromised memory

SYSTEM_STATE["memory"]["MEMORY-2701"]["enabled"] = False

record_action(
    f"ACT-{len(ACTIONS)+1:04d}",
    "MEMORY-2701",
    "quarantine_memory_store",
    "SUCCESS",
    "Compromised persistent memory removed from runtime access.",
)


# 5. Eradicate malicious memory state

SYSTEM_STATE["memory"]["MEMORY-2701"][
    "malicious_state_present"
] = False

SYSTEM_STATE["memory"]["MEMORY-2701"][
    "compromised"
] = False

record_action(
    f"ACT-{len(ACTIONS)+1:04d}",
    "MEMORY-2701",
    "eradicate_malicious_memory",
    "SUCCESS",
    "Persistent malicious instruction removed after evidence preservation.",
)


# 6. Restrict adjacent memory

SYSTEM_STATE["memory"]["MEMORY-2702"]["enabled"] = False

record_action(
    f"ACT-{len(ACTIONS)+1:04d}",
    "MEMORY-2702",
    "restrict_adjacent_memory",
    "SUCCESS",
    "Potentially exposed memory isolated pending integrity review.",
)


# 7. Quarantine poisoned RAG document

SYSTEM_STATE["rag"]["DOC-2791"]["available"] = False

record_action(
    f"ACT-{len(ACTIONS)+1:04d}",
    "DOC-2791",
    "quarantine_rag_document",
    "SUCCESS",
    "Known poisoned retrieval document removed from retrieval availability.",
)


# 8. Disable affected RAG store

SYSTEM_STATE["rag"]["RAG-2701"]["enabled"] = False

record_action(
    f"ACT-{len(ACTIONS)+1:04d}",
    "RAG-2701",
    "disable_rag_store",
    "SUCCESS",
    "Affected retrieval source isolated pending validation.",
)


# 9. Revoke privileged tool

SYSTEM_STATE["tools"]["delete_record"]["enabled"] = False

record_action(
    f"ACT-{len(ACTIONS)+1:04d}",
    "delete_record",
    "revoke_privileged_tool",
    "SUCCESS",
    "Privileged execution capability revoked during containment.",
)


# 10. Block restricted target

SYSTEM_STATE["targets"]["R-2799"]["access_blocked"] = True

record_action(
    f"ACT-{len(ACTIONS)+1:04d}",
    "R-2799",
    "block_target_access",
    "SUCCESS",
    "Restricted target protected from additional incident-related operations.",
)


# 11. Reset authorization boundary

SYSTEM_STATE["authorization"]["AUTHZ-2701"]["trusted"] = True
SYSTEM_STATE["authorization"]["AUTHZ-2701"]["bypass_observed"] = False

record_action(
    f"ACT-{len(ACTIONS)+1:04d}",
    "AUTHZ-2701",
    "reset_authorization_boundary",
    "SUCCESS",
    "Compromised authorization state invalidated and restored to fail-closed behavior.",
)


# 12. Suspend identity pending review

SYSTEM_STATE["identity"]["USER-2701"]["enabled"] = False

record_action(
    f"ACT-{len(ACTIONS)+1:04d}",
    "USER-2701",
    "temporarily_suspend_identity",
    "SUCCESS",
    "Potentially exposed identity suspended pending incident review.",
)


# 13. Restrict downstream service

SYSTEM_STATE["downstream_services"][
    "RECORD-SERVICE-2701"
]["enabled"] = False

record_action(
    f"ACT-{len(ACTIONS)+1:04d}",
    "RECORD-SERVICE-2701",
    "restrict_downstream_service",
    "SUCCESS",
    "Affected downstream service restricted pending integrity validation.",
)


# ============================================================
# POST-CONTAINMENT ATTACK RETEST
# ============================================================

ATTACK_RETESTS = []


def add_retest(
    test_id,
    attack_stage,
    blocked,
    blocked_by,
):

    ATTACK_RETESTS.append({
        "test_id": test_id,
        "attack_stage": attack_stage,
        "blocked": blocked,
        "blocked_by": blocked_by,
    })


add_retest(
    "RETEST-001",
    "reuse_compromised_session",
    not SYSTEM_STATE["sessions"]["SESSION-2701"]["active"],
    "SESSION_TERMINATION",
)

add_retest(
    "RETEST-002",
    "reuse_compromised_agent",
    not SYSTEM_STATE["agents"]["AGENT-2702"]["enabled"],
    "AGENT_DISABLEMENT",
)

add_retest(
    "RETEST-003",
    "retrieve_poisoned_document",
    not SYSTEM_STATE["rag"]["DOC-2791"]["available"],
    "RAG_QUARANTINE",
)

add_retest(
    "RETEST-004",
    "consume_persistent_malicious_memory",
    (
        not SYSTEM_STATE["memory"]["MEMORY-2701"]["enabled"]
        and
        not SYSTEM_STATE["memory"]["MEMORY-2701"][
            "malicious_state_present"
        ]
    ),
    "MEMORY_QUARANTINE_AND_ERADICATION",
)

add_retest(
    "RETEST-005",
    "invoke_privileged_delete_tool",
    not SYSTEM_STATE["tools"]["delete_record"]["enabled"],
    "PRIVILEGED_TOOL_REVOCATION",
)

add_retest(
    "RETEST-006",
    "access_restricted_target",
    SYSTEM_STATE["targets"]["R-2799"]["access_blocked"],
    "TARGET_ACCESS_BLOCK",
)

add_retest(
    "RETEST-007",
    "repeat_authorization_bypass",
    (
        SYSTEM_STATE["authorization"]["AUTHZ-2701"]["trusted"]
        and
        not SYSTEM_STATE["authorization"]["AUTHZ-2701"][
            "bypass_observed"
        ]
    ),
    "AUTHORIZATION_RESET",
)

add_retest(
    "RETEST-008",
    "reuse_suspect_identity",
    not SYSTEM_STATE["identity"]["USER-2701"]["enabled"],
    "IDENTITY_SUSPENSION",
)

add_retest(
    "RETEST-009",
    "repeat_downstream_execution",
    not SYSTEM_STATE["downstream_services"][
        "RECORD-SERVICE-2701"
    ]["enabled"],
    "DOWNSTREAM_SERVICE_RESTRICTION",
)


# ============================================================
# LEGITIMATE UTILITY CHECK
# ============================================================

# The normal non-privileged read tool is intentionally preserved.

LEGITIMATE_UTILITY = {
    "tool": "read_record",
    "enabled":
        SYSTEM_STATE["tools"]["read_record"]["enabled"],
    "privileged": False,
    "safe_utility_preserved":
        SYSTEM_STATE["tools"]["read_record"]["enabled"],
}


# ============================================================
# METRICS
# ============================================================

successful_actions = sum(
    1 for action in ACTIONS
    if action["result"] == "SUCCESS"
)

containment_action_success_rate = (
    successful_actions
    / len(ACTIONS)
    * 100
)

blocked_retests = sum(
    1 for test in ATTACK_RETESTS
    if test["blocked"]
)

attack_retest_block_rate = (
    blocked_retests
    / len(ATTACK_RETESTS)
    * 100
)

forensic_items_preserved = sum(
    1
    for preserved
    in FORENSIC_PRESERVATION.values()
    if preserved
)

forensic_preservation_rate = (
    forensic_items_preserved
    / len(FORENSIC_PRESERVATION)
    * 100
)


# ============================================================
# CONTAINMENT VALIDATION
# ============================================================

compromised_sessions_terminated = all(
    not SYSTEM_STATE["sessions"][session]["active"]
    for session in [
        "SESSION-2701",
        "SESSION-2702",
    ]
)

compromised_agents_disabled = all(
    not SYSTEM_STATE["agents"][agent]["enabled"]
    for agent in [
        "AGENT-2701",
        "AGENT-2702",
    ]
)

malicious_memory_eradicated = (
    not SYSTEM_STATE["memory"]["MEMORY-2701"][
        "malicious_state_present"
    ]
)

poisoned_rag_quarantined = (
    not SYSTEM_STATE["rag"]["DOC-2791"]["available"]
)

privileged_tool_revoked = (
    not SYSTEM_STATE["tools"]["delete_record"]["enabled"]
)

restricted_target_protected = (
    SYSTEM_STATE["targets"]["R-2799"]["access_blocked"]
)

authorization_boundary_restored = (
    SYSTEM_STATE["authorization"]["AUTHZ-2701"]["trusted"]
    and
    not SYSTEM_STATE["authorization"]["AUTHZ-2701"][
        "bypass_observed"
    ]
)

attack_chain_blocked = all(
    test["blocked"]
    for test in ATTACK_RETESTS
)

legitimate_utility_preserved = (
    LEGITIMATE_UTILITY["safe_utility_preserved"]
)

forensic_evidence_preserved = all(
    FORENSIC_PRESERVATION.values()
)


# ============================================================
# OUTPUT
# ============================================================

print(
    "\n=== Day 27 Lab 13: AI Incident Containment "
    "& Eradication Controls ==="
)


print("\n" + "=" * 82)
print("        CONTAINMENT & ERADICATION ACTIONS")
print("=" * 82)

for action in ACTIONS:

    print(
        f"{action['action_id']} | "
        f"{action['asset']} | "
        f"{action['action']} | "
        f"{action['result']}"
    )

    print(
        f"  Reason: {action['reason']}"
    )


print("\n" + "=" * 82)
print("        POST-CONTAINMENT ATTACK RETEST")
print("=" * 82)

for test in ATTACK_RETESTS:

    print(
        f"{test['test_id']} | "
        f"{test['attack_stage']} | "
        f"Blocked={test['blocked']} | "
        f"Control={test['blocked_by']}"
    )


print("\n" + "=" * 82)
print("        CONTAINMENT METRICS")
print("=" * 82)

print(
    f"Containment Actions: {len(ACTIONS)}"
)

print(
    f"Successful Containment Actions: "
    f"{successful_actions}"
)

print(
    f"Containment Action Success Rate: "
    f"{containment_action_success_rate:.2f}%"
)

print(
    f"Attack Retests: {len(ATTACK_RETESTS)}"
)

print(
    f"Blocked Attack Retests: {blocked_retests}"
)

print(
    f"Attack Retest Block Rate: "
    f"{attack_retest_block_rate:.2f}%"
)

print(
    f"Forensic Preservation Rate: "
    f"{forensic_preservation_rate:.2f}%"
)


print("\n" + "=" * 82)
print("        LEGITIMATE UTILITY CHECK")
print("=" * 82)

print(
    "Normal Tool:",
    LEGITIMATE_UTILITY["tool"],
)

print(
    "Normal Tool Enabled:",
    LEGITIMATE_UTILITY["enabled"],
)

print(
    "Safe Legitimate Utility Preserved:",
    LEGITIMATE_UTILITY[
        "safe_utility_preserved"
    ],
)


print("\n" + "=" * 82)
print("        INCIDENT CONTAINMENT SECURITY CHECKS")
print("=" * 82)

print(
    "Compromised Sessions Terminated:",
    compromised_sessions_terminated,
)

print(
    "Compromised Agents Disabled:",
    compromised_agents_disabled,
)

print(
    "Malicious Memory Eradicated:",
    malicious_memory_eradicated,
)

print(
    "Poisoned RAG Content Quarantined:",
    poisoned_rag_quarantined,
)

print(
    "Privileged Tool Revoked:",
    privileged_tool_revoked,
)

print(
    "Restricted Target Protected:",
    restricted_target_protected,
)

print(
    "Authorization Boundary Restored:",
    authorization_boundary_restored,
)

print(
    "Forensic Evidence Preserved:",
    forensic_evidence_preserved,
)

print(
    "Attack Chain Blocked:",
    attack_chain_blocked,
)

print(
    "Legitimate Utility Preserved:",
    legitimate_utility_preserved,
)


# ============================================================
# EXPORT EVIDENCE
# ============================================================

REPORT = {
    "lab": "Day 27 Lab 13",
    "incident_id": INCIDENT_ID,
    "trace_id": TRACE_ID,
    "containment_actions": ACTIONS,
    "attack_retests": ATTACK_RETESTS,
    "forensic_preservation":
        FORENSIC_PRESERVATION,
    "legitimate_utility":
        LEGITIMATE_UTILITY,
    "metrics": {
        "containment_actions":
            len(ACTIONS),
        "successful_actions":
            successful_actions,
        "containment_action_success_rate":
            containment_action_success_rate,
        "attack_retests":
            len(ATTACK_RETESTS),
        "blocked_attack_retests":
            blocked_retests,
        "attack_retest_block_rate":
            attack_retest_block_rate,
        "forensic_preservation_rate":
            forensic_preservation_rate,
    },
    "security_checks": {
        "compromised_sessions_terminated":
            compromised_sessions_terminated,
        "compromised_agents_disabled":
            compromised_agents_disabled,
        "malicious_memory_eradicated":
            malicious_memory_eradicated,
        "poisoned_rag_quarantined":
            poisoned_rag_quarantined,
        "privileged_tool_revoked":
            privileged_tool_revoked,
        "restricted_target_protected":
            restricted_target_protected,
        "authorization_boundary_restored":
            authorization_boundary_restored,
        "forensic_evidence_preserved":
            forensic_evidence_preserved,
        "attack_chain_blocked":
            attack_chain_blocked,
        "legitimate_utility_preserved":
            legitimate_utility_preserved,
    },
}


OUTPUT_FILE = (
    "day27-incident-containment-eradication-evidence.json"
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
    "Containment isolates the compromised sessions, agents, "
    "memory, retrieval content, privileged execution path, "
    "restricted target, identity, authorization boundary, and "
    "affected downstream service identified during blast-radius "
    "analysis."
)

print(
    "Eradication removes the persistent malicious memory state "
    "only after forensic evidence has been preserved."
)

print(
    "Post-containment adversarial retesting verifies that the "
    "known attack path can no longer reuse compromised state, "
    "retrieve poisoned content, invoke privileged execution, "
    "bypass authorization, or repeat downstream impact."
)

print(
    "The normal read-only workflow remains available, showing "
    "that incident containment does not require disabling every "
    "legitimate capability."
)

print("\nCore Principle:")

print(
    "If an AI security event cannot be observed and reconstructed, "
    "it cannot be reliably investigated or improved."
)