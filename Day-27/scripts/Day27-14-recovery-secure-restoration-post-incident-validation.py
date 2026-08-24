"""
Day 27 Lab 14
Recovery, Secure Restoration & Post-Incident Validation

Purpose:
Simulate controlled recovery of an AI system following containment
and eradication of a multi-stage AI security incident.

The lab verifies that compromised state has been removed, trust
boundaries have been restored, services can be progressively
re-enabled, adversarial attack paths remain blocked, and legitimate
utility returns safely.

Core Principle:
If an AI security event cannot be observed and reconstructed,
it cannot be reliably investigated or improved.
"""

import json
from datetime import datetime, timezone


INCIDENT_ID = "INC-2714"
TRACE_ID = "TRACE-2714"
RECOVERY_ID = "RECOVERY-2714"


# ============================================================
# POST-CONTAINMENT STARTING STATE
# ============================================================

SYSTEM_STATE = {

    "sessions": {
        "SESSION-2701": {
            "active": False,
            "compromised": False,
            "retired": True,
        },

        "SESSION-2702": {
            "active": False,
            "compromised": False,
            "retired": True,
        },

        "SESSION-2703": {
            "active": False,
            "validated": False,
        },
    },

    "agents": {
        "AGENT-2701": {
            "enabled": False,
            "validated": False,
        },

        "AGENT-2702": {
            "enabled": False,
            "validated": False,
        },
    },

    "memory": {
        "MEMORY-2701": {
            "enabled": False,
            "malicious_state_present": False,
            "integrity_validated": False,
        },

        "MEMORY-2702": {
            "enabled": False,
            "malicious_state_present": False,
            "integrity_validated": False,
        },
    },

    "rag": {
        "DOC-2791": {
            "available": False,
            "poisoned": True,
            "quarantined": True,
        },

        "RAG-2701": {
            "enabled": False,
            "integrity_validated": False,
        },

        "DOC-2702": {
            "available": True,
            "trusted": True,
            "poisoned": False,
        },
    },

    "tools": {
        "read_record": {
            "enabled": True,
            "privileged": False,
        },

        "summarize_project": {
            "enabled": True,
            "privileged": False,
        },

        "delete_record": {
            "enabled": False,
            "privileged": True,
            "requires_explicit_authorization": True,
        },
    },

    "authorization": {
        "AUTHZ-2701": {
            "trusted": True,
            "fail_closed": True,
            "validated": False,
        }
    },

    "targets": {
        "R-2702": {
            "restricted": False,
            "available": True,
        },

        "R-2799": {
            "restricted": True,
            "access_blocked": True,
        },
    },

    "identity": {
        "USER-2701": {
            "enabled": False,
            "validated": False,
        }
    },

    "downstream_services": {
        "RECORD-SERVICE-2701": {
            "enabled": False,
            "integrity_validated": False,
        }
    },
}


# ============================================================
# RECOVERY ACTION LOG
# ============================================================

RECOVERY_ACTIONS = []


def recovery_action(
    asset,
    action,
    result,
    reason,
):

    RECOVERY_ACTIONS.append({
        "action_id": f"REC-{len(RECOVERY_ACTIONS)+1:04d}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "asset": asset,
        "action": action,
        "result": result,
        "reason": reason,
    })


# ============================================================
# PHASE 1 — VERIFY ERADICATION
# ============================================================

memory_clean = (
    not SYSTEM_STATE["memory"]["MEMORY-2701"][
        "malicious_state_present"
    ]
)

recovery_action(
    "MEMORY-2701",
    "verify_malicious_state_removed",
    "SUCCESS" if memory_clean else "FAILURE",
    "Persistent malicious memory state must be absent before recovery.",
)


poisoned_document_isolated = (
    not SYSTEM_STATE["rag"]["DOC-2791"]["available"]
    and
    SYSTEM_STATE["rag"]["DOC-2791"]["quarantined"]
)

recovery_action(
    "DOC-2791",
    "verify_poisoned_document_quarantine",
    "SUCCESS" if poisoned_document_isolated else "FAILURE",
    "Known poisoned retrieval content must remain unavailable.",
)


restricted_target_protected = (
    SYSTEM_STATE["targets"]["R-2799"]["access_blocked"]
)

recovery_action(
    "R-2799",
    "verify_restricted_target_protection",
    "SUCCESS" if restricted_target_protected else "FAILURE",
    "Restricted target remains protected during recovery.",
)


# ============================================================
# PHASE 2 — VALIDATE TRUSTED COMPONENTS
# ============================================================

SYSTEM_STATE["memory"]["MEMORY-2701"][
    "integrity_validated"
] = True

SYSTEM_STATE["memory"]["MEMORY-2702"][
    "integrity_validated"
] = True

recovery_action(
    "MEMORY-2701",
    "validate_memory_integrity",
    "SUCCESS",
    "Memory store validated after malicious state eradication.",
)

recovery_action(
    "MEMORY-2702",
    "validate_adjacent_memory_integrity",
    "SUCCESS",
    "Adjacent memory store reviewed and found clean.",
)


SYSTEM_STATE["rag"]["RAG-2701"][
    "integrity_validated"
] = True

recovery_action(
    "RAG-2701",
    "validate_rag_store_integrity",
    "SUCCESS",
    "Retrieval store validated with poisoned document excluded.",
)


SYSTEM_STATE["authorization"]["AUTHZ-2701"][
    "validated"
] = True

recovery_action(
    "AUTHZ-2701",
    "validate_authorization_boundary",
    "SUCCESS",
    "Authorization boundary verified to operate fail-closed.",
)


SYSTEM_STATE["downstream_services"][
    "RECORD-SERVICE-2701"
]["integrity_validated"] = True

recovery_action(
    "RECORD-SERVICE-2701",
    "validate_downstream_service_integrity",
    "SUCCESS",
    "Downstream record service validated before restoration.",
)


SYSTEM_STATE["identity"]["USER-2701"][
    "validated"
] = True

recovery_action(
    "USER-2701",
    "validate_identity",
    "SUCCESS",
    "Identity reviewed before access restoration.",
)


# ============================================================
# PHASE 3 — CONTROLLED SERVICE RESTORATION
# ============================================================

SYSTEM_STATE["memory"]["MEMORY-2701"]["enabled"] = True
SYSTEM_STATE["memory"]["MEMORY-2702"]["enabled"] = True

recovery_action(
    "MEMORY-2701",
    "restore_memory_service",
    "SUCCESS",
    "Validated clean memory restored to runtime.",
)

recovery_action(
    "MEMORY-2702",
    "restore_adjacent_memory_service",
    "SUCCESS",
    "Validated adjacent memory restored.",
)


SYSTEM_STATE["rag"]["RAG-2701"]["enabled"] = True

recovery_action(
    "RAG-2701",
    "restore_rag_service",
    "SUCCESS",
    "Validated retrieval service restored without poisoned document.",
)


SYSTEM_STATE["downstream_services"][
    "RECORD-SERVICE-2701"
]["enabled"] = True

recovery_action(
    "RECORD-SERVICE-2701",
    "restore_downstream_service",
    "SUCCESS",
    "Validated downstream service returned to operation.",
)


SYSTEM_STATE["identity"]["USER-2701"]["enabled"] = True

recovery_action(
    "USER-2701",
    "restore_identity_access",
    "SUCCESS",
    "Reviewed identity restored after validation.",
)


# ============================================================
# PHASE 4 — RESTORE AGENTS SAFELY
# ============================================================

for agent_id in ["AGENT-2701", "AGENT-2702"]:

    SYSTEM_STATE["agents"][agent_id][
        "validated"
    ] = True

    SYSTEM_STATE["agents"][agent_id][
        "enabled"
    ] = True

    recovery_action(
        agent_id,
        "restore_validated_agent",
        "SUCCESS",
        "Agent restored only after trust-boundary validation.",
    )


# ============================================================
# PHASE 5 — CREATE CLEAN SESSION
# ============================================================

SYSTEM_STATE["sessions"]["SESSION-2703"][
    "validated"
] = True

SYSTEM_STATE["sessions"]["SESSION-2703"][
    "active"
] = True

recovery_action(
    "SESSION-2703",
    "activate_clean_session",
    "SUCCESS",
    "New validated session activated after recovery controls passed.",
)


# ============================================================
# PRIVILEGED TOOL POLICY
# ============================================================

# The privileged tool is intentionally NOT automatically restored.
# It remains disabled until separate privileged-access approval.

privileged_tool_safely_disabled = (
    not SYSTEM_STATE["tools"]["delete_record"]["enabled"]
)

recovery_action(
    "delete_record",
    "retain_privileged_tool_restriction",
    "SUCCESS" if privileged_tool_safely_disabled else "FAILURE",
    "Privileged tool remains disabled until explicit reauthorization.",
)


# ============================================================
# POST-RECOVERY ADVERSARIAL VALIDATION
# ============================================================

SECURITY_TESTS = []


def add_security_test(
    test_id,
    scenario,
    passed,
    control,
):

    SECURITY_TESTS.append({
        "test_id": test_id,
        "scenario": scenario,
        "passed": passed,
        "control": control,
    })


add_security_test(
    "POST-IR-001",
    "poisoned_rag_document_retrieval",
    not SYSTEM_STATE["rag"]["DOC-2791"]["available"],
    "RAG_QUARANTINE",
)

add_security_test(
    "POST-IR-002",
    "persistent_memory_reinfection",
    not SYSTEM_STATE["memory"]["MEMORY-2701"][
        "malicious_state_present"
    ],
    "MEMORY_ERADICATION",
)

add_security_test(
    "POST-IR-003",
    "restricted_target_access",
    SYSTEM_STATE["targets"]["R-2799"]["access_blocked"],
    "TARGET_PROTECTION",
)

add_security_test(
    "POST-IR-004",
    "privileged_delete_execution",
    not SYSTEM_STATE["tools"]["delete_record"]["enabled"],
    "PRIVILEGED_TOOL_RESTRICTION",
)

add_security_test(
    "POST-IR-005",
    "authorization_bypass",
    (
        SYSTEM_STATE["authorization"]["AUTHZ-2701"]["trusted"]
        and
        SYSTEM_STATE["authorization"]["AUTHZ-2701"]["fail_closed"]
        and
        SYSTEM_STATE["authorization"]["AUTHZ-2701"]["validated"]
    ),
    "FAIL_CLOSED_AUTHORIZATION",
)

add_security_test(
    "POST-IR-006",
    "unvalidated_memory_use",
    (
        SYSTEM_STATE["memory"]["MEMORY-2701"][
            "integrity_validated"
        ]
        and
        SYSTEM_STATE["memory"]["MEMORY-2702"][
            "integrity_validated"
        ]
    ),
    "MEMORY_INTEGRITY_VALIDATION",
)

add_security_test(
    "POST-IR-007",
    "unvalidated_rag_restoration",
    (
        SYSTEM_STATE["rag"]["RAG-2701"][
            "integrity_validated"
        ]
        and
        SYSTEM_STATE["rag"]["RAG-2701"]["enabled"]
    ),
    "RAG_RECOVERY_VALIDATION",
)

add_security_test(
    "POST-IR-008",
    "unsafe_downstream_restoration",
    (
        SYSTEM_STATE["downstream_services"][
            "RECORD-SERVICE-2701"
        ]["integrity_validated"]
        and
        SYSTEM_STATE["downstream_services"][
            "RECORD-SERVICE-2701"
        ]["enabled"]
    ),
    "DOWNSTREAM_INTEGRITY_VALIDATION",
)


# ============================================================
# LEGITIMATE UTILITY VALIDATION
# ============================================================

UTILITY_TESTS = []


def add_utility_test(
    test_id,
    scenario,
    completed,
):

    UTILITY_TESTS.append({
        "test_id": test_id,
        "scenario": scenario,
        "completed": completed,
    })


add_utility_test(
    "UTIL-REC-001",
    "authorized_record_read",
    (
        SYSTEM_STATE["tools"]["read_record"]["enabled"]
        and
        SYSTEM_STATE["targets"]["R-2702"]["available"]
    ),
)

add_utility_test(
    "UTIL-REC-002",
    "project_summary",
    SYSTEM_STATE["tools"][
        "summarize_project"
    ]["enabled"],
)

add_utility_test(
    "UTIL-REC-003",
    "trusted_rag_retrieval",
    (
        SYSTEM_STATE["rag"]["RAG-2701"]["enabled"]
        and
        SYSTEM_STATE["rag"]["DOC-2702"]["available"]
        and
        SYSTEM_STATE["rag"]["DOC-2702"]["trusted"]
    ),
)

add_utility_test(
    "UTIL-REC-004",
    "clean_memory_access",
    (
        SYSTEM_STATE["memory"]["MEMORY-2701"]["enabled"]
        and
        SYSTEM_STATE["memory"]["MEMORY-2701"][
            "integrity_validated"
        ]
    ),
)

add_utility_test(
    "UTIL-REC-005",
    "validated_agent_operation",
    (
        SYSTEM_STATE["agents"]["AGENT-2701"]["enabled"]
        and
        SYSTEM_STATE["agents"]["AGENT-2701"]["validated"]
    ),
)


# ============================================================
# METRICS
# ============================================================

successful_recovery_actions = sum(
    1
    for action in RECOVERY_ACTIONS
    if action["result"] == "SUCCESS"
)

recovery_action_success_rate = (
    successful_recovery_actions
    / len(RECOVERY_ACTIONS)
    * 100
)


passed_security_tests = sum(
    1
    for test in SECURITY_TESTS
    if test["passed"]
)

post_recovery_security_pass_rate = (
    passed_security_tests
    / len(SECURITY_TESTS)
    * 100
)


completed_utility_tests = sum(
    1
    for test in UTILITY_TESTS
    if test["completed"]
)

utility_completion_rate = (
    completed_utility_tests
    / len(UTILITY_TESTS)
    * 100
)


false_block_rate = (
    (
        len(UTILITY_TESTS)
        - completed_utility_tests
    )
    / len(UTILITY_TESTS)
    * 100
)


# ============================================================
# FINAL RECOVERY CHECKS
# ============================================================

malicious_memory_absent = (
    not SYSTEM_STATE["memory"]["MEMORY-2701"][
        "malicious_state_present"
    ]
)

poisoned_content_remains_quarantined = (
    not SYSTEM_STATE["rag"]["DOC-2791"]["available"]
)

authorization_secure = (
    SYSTEM_STATE["authorization"]["AUTHZ-2701"]["trusted"]
    and
    SYSTEM_STATE["authorization"]["AUTHZ-2701"]["fail_closed"]
    and
    SYSTEM_STATE["authorization"]["AUTHZ-2701"]["validated"]
)

restricted_target_secure = (
    SYSTEM_STATE["targets"]["R-2799"]["access_blocked"]
)

privileged_execution_restricted = (
    not SYSTEM_STATE["tools"]["delete_record"]["enabled"]
)

all_security_tests_pass = all(
    test["passed"]
    for test in SECURITY_TESTS
)

all_utility_tests_pass = all(
    test["completed"]
    for test in UTILITY_TESTS
)

recovery_approved = (
    malicious_memory_absent
    and
    poisoned_content_remains_quarantined
    and
    authorization_secure
    and
    restricted_target_secure
    and
    privileged_execution_restricted
    and
    all_security_tests_pass
    and
    all_utility_tests_pass
)


# ============================================================
# OUTPUT
# ============================================================

print(
    "\n=== Day 27 Lab 14: Recovery, Secure Restoration "
    "& Post-Incident Validation ==="
)


print("\n" + "=" * 84)
print("        CONTROLLED RECOVERY ACTIONS")
print("=" * 84)

for action in RECOVERY_ACTIONS:

    print(
        f"{action['action_id']} | "
        f"{action['asset']} | "
        f"{action['action']} | "
        f"{action['result']}"
    )

    print(
        f"  Reason: {action['reason']}"
    )


print("\n" + "=" * 84)
print("        POST-RECOVERY ADVERSARIAL VALIDATION")
print("=" * 84)

for test in SECURITY_TESTS:

    print(
        f"{test['test_id']} | "
        f"{test['scenario']} | "
        f"Passed={test['passed']} | "
        f"Control={test['control']}"
    )


print("\n" + "=" * 84)
print("        POST-RECOVERY LEGITIMATE UTILITY")
print("=" * 84)

for test in UTILITY_TESTS:

    print(
        f"{test['test_id']} | "
        f"{test['scenario']} | "
        f"Completed={test['completed']}"
    )


print("\n" + "=" * 84)
print("        RECOVERY METRICS")
print("=" * 84)

print(
    f"Recovery Actions: {len(RECOVERY_ACTIONS)}"
)

print(
    f"Successful Recovery Actions: "
    f"{successful_recovery_actions}"
)

print(
    f"Recovery Action Success Rate: "
    f"{recovery_action_success_rate:.2f}%"
)

print(
    f"Post-Recovery Security Tests: "
    f"{len(SECURITY_TESTS)}"
)

print(
    f"Passed Security Tests: "
    f"{passed_security_tests}"
)

print(
    f"Post-Recovery Security Pass Rate: "
    f"{post_recovery_security_pass_rate:.2f}%"
)

print(
    f"Legitimate Utility Tests: "
    f"{len(UTILITY_TESTS)}"
)

print(
    f"Completed Utility Tests: "
    f"{completed_utility_tests}"
)

print(
    f"Legitimate Workflow Completion Rate: "
    f"{utility_completion_rate:.2f}%"
)

print(
    f"False Block Rate: "
    f"{false_block_rate:.2f}%"
)


print("\n" + "=" * 84)
print("        POST-INCIDENT RECOVERY SECURITY CHECKS")
print("=" * 84)

print(
    "Malicious Memory Absent:",
    malicious_memory_absent,
)

print(
    "Poisoned Content Remains Quarantined:",
    poisoned_content_remains_quarantined,
)

print(
    "Authorization Boundary Secure:",
    authorization_secure,
)

print(
    "Restricted Target Secure:",
    restricted_target_secure,
)

print(
    "Privileged Execution Still Restricted:",
    privileged_execution_restricted,
)

print(
    "All Adversarial Recovery Tests Pass:",
    all_security_tests_pass,
)

print(
    "All Legitimate Utility Tests Pass:",
    all_utility_tests_pass,
)

print(
    "Recovery Approved:",
    recovery_approved,
)


# ============================================================
# EVIDENCE EXPORT
# ============================================================

REPORT = {

    "lab": "Day 27 Lab 14",

    "incident_id": INCIDENT_ID,

    "trace_id": TRACE_ID,

    "recovery_id": RECOVERY_ID,

    "recovery_actions":
        RECOVERY_ACTIONS,

    "security_tests":
        SECURITY_TESTS,

    "utility_tests":
        UTILITY_TESTS,

    "metrics": {

        "recovery_actions":
            len(RECOVERY_ACTIONS),

        "successful_recovery_actions":
            successful_recovery_actions,

        "recovery_action_success_rate":
            recovery_action_success_rate,

        "post_recovery_security_tests":
            len(SECURITY_TESTS),

        "passed_security_tests":
            passed_security_tests,

        "post_recovery_security_pass_rate":
            post_recovery_security_pass_rate,

        "utility_tests":
            len(UTILITY_TESTS),

        "completed_utility_tests":
            completed_utility_tests,

        "utility_completion_rate":
            utility_completion_rate,

        "false_block_rate":
            false_block_rate,
    },

    "security_checks": {

        "malicious_memory_absent":
            malicious_memory_absent,

        "poisoned_content_remains_quarantined":
            poisoned_content_remains_quarantined,

        "authorization_secure":
            authorization_secure,

        "restricted_target_secure":
            restricted_target_secure,

        "privileged_execution_restricted":
            privileged_execution_restricted,

        "all_security_tests_pass":
            all_security_tests_pass,

        "all_utility_tests_pass":
            all_utility_tests_pass,

        "recovery_approved":
            recovery_approved,
    },
}


OUTPUT_FILE = (
    "day27-secure-recovery-validation-evidence.json"
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
    "Recovery is performed as a controlled security process rather "
    "than simply re-enabling every component that was disabled "
    "during containment."
)

print(
    "Persistent malicious memory is verified absent, poisoned "
    "retrieval content remains quarantined, affected stores and "
    "services are integrity-validated, the authorization boundary "
    "is confirmed fail-closed, and the restricted target remains "
    "protected."
)

print(
    "The privileged delete capability is intentionally not restored "
    "automatically. High-risk capabilities require separate "
    "authorization rather than inheriting trust from general "
    "service recovery."
)

print(
    "Post-recovery adversarial tests verify that the known incident "
    "path remains blocked, while legitimate utility tests confirm "
    "that normal AI workflows have returned without unnecessary "
    "over-blocking."
)

print("\nCore Principle:")

print(
    "If an AI security event cannot be observed and reconstructed, "
    "it cannot be reliably investigated or improved."
)