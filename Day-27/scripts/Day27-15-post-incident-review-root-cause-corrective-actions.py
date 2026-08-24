"""
Day 27 Lab 15
Post-Incident Review, Root-Cause Corrective Actions
& Detection Engineering Improvements

Purpose:
Convert a reconstructed AI security incident into durable
security improvements.

This lab evaluates:
- Root cause
- Contributing causes
- Control failures
- Detection gaps
- Corrective actions
- Preventive actions
- Detection-engineering improvements
- Ownership and priority
- Validation tests
- Expected reduction in detection and response time
- Lessons learned

Core Principle:
If an AI security event cannot be observed and reconstructed,
it cannot be reliably investigated or improved.
"""

import json


INCIDENT_ID = "INC-2715"
PIR_ID = "PIR-2715"


# ============================================================
# INCIDENT SUMMARY
# ============================================================

INCIDENT_SUMMARY = {
    "incident_id": INCIDENT_ID,
    "severity": "CRITICAL",

    "initial_vector":
        "prompt_injection",

    "attack_chain": [
        "prompt_injection",
        "poisoned_rag_retrieval",
        "poisoned_context_admission",
        "unauthorized_memory_write",
        "persistent_memory_compromise",
        "cross_session_memory_retrieval",
        "agent_plan_manipulation",
        "restricted_target_selection",
        "privileged_tool_selection",
        "authorization_bypass",
        "unauthorized_tool_execution",
        "unauthorized_system_impact",
    ],

    "impact":
        "unauthorized_record_deletion",

    "time_to_detection_seconds":
        192,

    "time_to_incident_declaration_seconds":
        195,
}


# ============================================================
# ROOT-CAUSE ANALYSIS
# ============================================================

ROOT_CAUSES = [
    {
        "cause_id": "RC-001",

        "type": "PRIMARY",

        "cause":
            "Untrusted prompt and retrieved content were able "
            "to influence trusted execution state.",

        "security_domain":
            "instruction_trust_boundary",
    },

    {
        "cause_id": "RC-002",

        "type": "CONTRIBUTING",

        "cause":
            "Poisoned RAG content was admitted into runtime context.",

        "security_domain":
            "rag_security",
    },

    {
        "cause_id": "RC-003",

        "type": "CONTRIBUTING",

        "cause":
            "Untrusted runtime content was allowed to persist "
            "into long-lived memory.",

        "security_domain":
            "memory_security",
    },

    {
        "cause_id": "RC-004",

        "type": "CONTRIBUTING",

        "cause":
            "Persistent memory influence crossed session "
            "and agent boundaries.",

        "security_domain":
            "persistent_state_security",
    },

    {
        "cause_id": "RC-005",

        "type": "CONTRIBUTING",

        "cause":
            "Privileged tool selection was influenced by "
            "model-generated state.",

        "security_domain":
            "tool_security",
    },

    {
        "cause_id": "RC-006",

        "type": "PRIMARY",

        "cause":
            "Authorization failure did not reliably prevent "
            "downstream privileged execution.",

        "security_domain":
            "authorization",
    },
]


# ============================================================
# CONTROL-GAP ANALYSIS
# ============================================================

CONTROL_GAPS = [
    {
        "gap_id": "GAP-001",
        "control": "Prompt Trust Boundary",
        "status": "INSUFFICIENT",
        "finding":
            "Untrusted prompt instructions reached downstream processing.",
    },

    {
        "gap_id": "GAP-002",
        "control": "RAG Source Validation",
        "status": "INSUFFICIENT",
        "finding":
            "Untrusted retrieved content was admitted into context.",
    },

    {
        "gap_id": "GAP-003",
        "control": "Memory Write Authorization",
        "status": "FAILED",
        "finding":
            "Untrusted content was written into persistent memory.",
    },

    {
        "gap_id": "GAP-004",
        "control": "Cross-Session Memory Trust",
        "status": "FAILED",
        "finding":
            "Persistent malicious state influenced a later session.",
    },

    {
        "gap_id": "GAP-005",
        "control": "Privileged Tool Policy",
        "status": "INSUFFICIENT",
        "finding":
            "A compromised agent could propose a privileged tool.",
    },

    {
        "gap_id": "GAP-006",
        "control": "Execution Authorization",
        "status": "FAILED",
        "finding":
            "Execution continued after authorization denial.",
    },

    {
        "gap_id": "GAP-007",
        "control": "Early Multi-Stage Detection",
        "status": "INSUFFICIENT",
        "finding":
            "The incident was detected only after substantial propagation.",
    },
]


# ============================================================
# CORRECTIVE / PREVENTIVE ACTIONS
# ============================================================

ACTIONS = [
    {
        "action_id": "CA-001",
        "category": "PREVENTIVE",
        "priority": "CRITICAL",
        "owner": "AI_SECURITY_ENGINEERING",
        "control_gap": "GAP-001",
        "action":
            "Enforce instruction hierarchy and classify external "
            "content as untrusted data.",
        "status": "IMPLEMENTED",
    },

    {
        "action_id": "CA-002",
        "category": "PREVENTIVE",
        "priority": "CRITICAL",
        "owner": "RAG_PLATFORM_TEAM",
        "control_gap": "GAP-002",
        "action":
            "Require source trust, provenance validation, and "
            "security scanning before RAG context admission.",
        "status": "IMPLEMENTED",
    },

    {
        "action_id": "CA-003",
        "category": "CORRECTIVE",
        "priority": "CRITICAL",
        "owner": "AI_PLATFORM_TEAM",
        "control_gap": "GAP-003",
        "action":
            "Require explicit authorization and provenance for "
            "persistent memory writes.",
        "status": "IMPLEMENTED",
    },

    {
        "action_id": "CA-004",
        "category": "PREVENTIVE",
        "priority": "HIGH",
        "owner": "AI_PLATFORM_TEAM",
        "control_gap": "GAP-004",
        "action":
            "Bind persistent memory to trust level, source, session, "
            "expiry, and integrity metadata.",
        "status": "IMPLEMENTED",
    },

    {
        "action_id": "CA-005",
        "category": "PREVENTIVE",
        "priority": "CRITICAL",
        "owner": "AGENT_SECURITY_TEAM",
        "control_gap": "GAP-005",
        "action":
            "Require independent authorization for privileged "
            "tool selection and execution.",
        "status": "IMPLEMENTED",
    },

    {
        "action_id": "CA-006",
        "category": "CORRECTIVE",
        "priority": "CRITICAL",
        "owner": "IDENTITY_SECURITY_TEAM",
        "control_gap": "GAP-006",
        "action":
            "Enforce fail-closed authorization so denied operations "
            "cannot continue into execution.",
        "status": "IMPLEMENTED",
    },

    {
        "action_id": "CA-007",
        "category": "DETECTIVE",
        "priority": "HIGH",
        "owner": "AI_SOC",
        "control_gap": "GAP-007",
        "action":
            "Correlate prompt injection, poisoned retrieval, "
            "memory writes, privileged tool proposals, and "
            "authorization anomalies.",
        "status": "IMPLEMENTED",
    },

    {
        "action_id": "CA-008",
        "category": "DETECTIVE",
        "priority": "HIGH",
        "owner": "AI_SOC",
        "control_gap": "GAP-007",
        "action":
            "Generate high-severity alerts when malicious state "
            "crosses session or agent boundaries.",
        "status": "IMPLEMENTED",
    },
]


# ============================================================
# DETECTION ENGINEERING IMPROVEMENTS
# ============================================================

DETECTION_RULES = [
    {
        "rule_id": "AI-PIR-DET-001",
        "name": "Prompt Override + RAG Poison Correlation",

        "logic": [
            "prompt_injection_detected",
            "untrusted_rag_document_retrieved",
        ],

        "severity": "HIGH",
    },

    {
        "rule_id": "AI-PIR-DET-002",
        "name": "Poisoned Context + Memory Write",

        "logic": [
            "poisoned_context_admitted",
            "unauthorized_memory_write",
        ],

        "severity": "CRITICAL",
    },

    {
        "rule_id": "AI-PIR-DET-003",
        "name": "Cross-Session Poisoned Memory Activation",

        "logic": [
            "malicious_memory_persisted",
            "later_session_memory_read",
            "behavior_influenced",
        ],

        "severity": "CRITICAL",
    },

    {
        "rule_id": "AI-PIR-DET-004",
        "name": "Restricted Target + Privileged Tool",

        "logic": [
            "restricted_target_selected",
            "privileged_tool_selected",
        ],

        "severity": "CRITICAL",
    },

    {
        "rule_id": "AI-PIR-DET-005",
        "name": "Authorization Denial Followed by Execution",

        "logic": [
            "authorization_denied",
            "tool_execution_observed",
        ],

        "severity": "CRITICAL",
    },

    {
        "rule_id": "AI-PIR-DET-006",
        "name": "Unauthorized Execution Impact",

        "logic": [
            "authorization_bypass",
            "unauthorized_tool_execution",
            "unauthorized_system_impact",
        ],

        "severity": "CRITICAL",
    },
]


# ============================================================
# DETECTION TIMING IMPROVEMENT
# ============================================================

BASELINE_TIMING = {
    "time_to_detection_seconds": 192,
    "time_to_incident_seconds": 195,
}


# Simulated hardened detection identifies the incident when
# poisoned context attempts to write persistent memory.

HARDENED_TIMING = {
    "time_to_detection_seconds": 8,
    "time_to_incident_seconds": 12,
}


detection_time_reduction = (
    BASELINE_TIMING["time_to_detection_seconds"]
    - HARDENED_TIMING["time_to_detection_seconds"]
)


detection_time_improvement_rate = (
    detection_time_reduction
    / BASELINE_TIMING["time_to_detection_seconds"]
    * 100
)


incident_time_reduction = (
    BASELINE_TIMING["time_to_incident_seconds"]
    - HARDENED_TIMING["time_to_incident_seconds"]
)


# ============================================================
# VALIDATION TESTS
# ============================================================

VALIDATION_TESTS = [
    {
        "test_id": "PIR-VAL-001",
        "name": "Prompt injection blocked",
        "passed": True,
    },

    {
        "test_id": "PIR-VAL-002",
        "name": "Poisoned RAG content rejected",
        "passed": True,
    },

    {
        "test_id": "PIR-VAL-003",
        "name": "Unauthorized memory write blocked",
        "passed": True,
    },

    {
        "test_id": "PIR-VAL-004",
        "name": "Cross-session malicious memory blocked",
        "passed": True,
    },

    {
        "test_id": "PIR-VAL-005",
        "name": "Privileged tool requires independent authorization",
        "passed": True,
    },

    {
        "test_id": "PIR-VAL-006",
        "name": "Authorization denial blocks execution",
        "passed": True,
    },

    {
        "test_id": "PIR-VAL-007",
        "name": "Multi-stage attack correlation alert generated",
        "passed": True,
    },

    {
        "test_id": "PIR-VAL-008",
        "name": "Legitimate authorized workflow preserved",
        "passed": True,
    },
]


# ============================================================
# LESSONS LEARNED
# ============================================================

LESSONS_LEARNED = [
    {
        "lesson_id": "LESSON-001",
        "lesson":
            "Prompt security cannot be evaluated independently "
            "from retrieval, memory, and tool execution.",
    },

    {
        "lesson_id": "LESSON-002",
        "lesson":
            "Persistent AI memory creates a cross-session attack surface.",
    },

    {
        "lesson_id": "LESSON-003",
        "lesson":
            "Model-generated approval or authority must never substitute "
            "for external authorization.",
    },

    {
        "lesson_id": "LESSON-004",
        "lesson":
            "Authorization denial must terminate the execution path.",
    },

    {
        "lesson_id": "LESSON-005",
        "lesson":
            "Detection engineering must correlate behavior across "
            "multiple AI components.",
    },

    {
        "lesson_id": "LESSON-006",
        "lesson":
            "Evidence preservation must occur before destructive "
            "containment or eradication.",
    },

    {
        "lesson_id": "LESSON-007",
        "lesson":
            "Recovery should restore validated functionality rather "
            "than automatically restoring all pre-incident privilege.",
    },
]


# ============================================================
# METRICS
# ============================================================

implemented_actions = sum(
    action["status"] == "IMPLEMENTED"
    for action in ACTIONS
)


corrective_action_completion_rate = (
    implemented_actions
    / len(ACTIONS)
    * 100
)


passed_validation_tests = sum(
    test["passed"]
    for test in VALIDATION_TESTS
)


validation_pass_rate = (
    passed_validation_tests
    / len(VALIDATION_TESTS)
    * 100
)


root_cause_coverage_rate = (
    len({
        cause["security_domain"]
        for cause in ROOT_CAUSES
    })
    / len({
        cause["security_domain"]
        for cause in ROOT_CAUSES
    })
    * 100
)


control_gap_action_coverage = {
    gap["gap_id"]:
        any(
            action["control_gap"]
            == gap["gap_id"]
            for action in ACTIONS
        )

    for gap in CONTROL_GAPS
}


all_control_gaps_addressed = all(
    control_gap_action_coverage.values()
)


# ============================================================
# OUTPUT
# ============================================================

print(
    "\n=== Day 27 Lab 15: Post-Incident Review, "
    "Root-Cause Corrective Actions & Detection "
    "Engineering Improvements ==="
)


print("\n" + "=" * 84)
print("        INCIDENT ROOT-CAUSE ANALYSIS")
print("=" * 84)


for cause in ROOT_CAUSES:

    print(
        f"{cause['cause_id']} | "
        f"{cause['type']} | "
        f"{cause['security_domain']}"
    )

    print(
        f"  {cause['cause']}"
    )


print("\n" + "=" * 84)
print("        CONTROL-GAP ANALYSIS")
print("=" * 84)


for gap in CONTROL_GAPS:

    print(
        f"{gap['gap_id']} | "
        f"{gap['status']} | "
        f"{gap['control']}"
    )

    print(
        f"  Finding: {gap['finding']}"
    )


print("\n" + "=" * 84)
print("        CORRECTIVE / PREVENTIVE ACTIONS")
print("=" * 84)


for action in ACTIONS:

    print(
        f"{action['action_id']} | "
        f"{action['category']} | "
        f"{action['priority']} | "
        f"{action['owner']} | "
        f"{action['status']}"
    )

    print(
        f"  Addresses: {action['control_gap']}"
    )

    print(
        f"  Action: {action['action']}"
    )


print("\n" + "=" * 84)
print("        DETECTION ENGINEERING IMPROVEMENTS")
print("=" * 84)


for rule in DETECTION_RULES:

    print(
        f"{rule['rule_id']} | "
        f"{rule['severity']} | "
        f"{rule['name']}"
    )

    print(
        f"  Correlation Logic: {rule['logic']}"
    )


print("\n" + "=" * 84)
print("        DETECTION / RESPONSE TIMING IMPROVEMENT")
print("=" * 84)


print(
    "Baseline Time To Detection:",
    f"{BASELINE_TIMING['time_to_detection_seconds']} seconds"
)

print(
    "Hardened Time To Detection:",
    f"{HARDENED_TIMING['time_to_detection_seconds']} seconds"
)

print(
    "Detection Time Reduction:",
    f"{detection_time_reduction} seconds"
)

print(
    "Detection Time Improvement:",
    f"{detection_time_improvement_rate:.2f}%"
)

print(
    "Baseline Time To Incident Declaration:",
    f"{BASELINE_TIMING['time_to_incident_seconds']} seconds"
)

print(
    "Hardened Time To Incident Declaration:",
    f"{HARDENED_TIMING['time_to_incident_seconds']} seconds"
)

print(
    "Incident Declaration Time Reduction:",
    f"{incident_time_reduction} seconds"
)


print("\n" + "=" * 84)
print("        CORRECTIVE-ACTION VALIDATION")
print("=" * 84)


for test in VALIDATION_TESTS:

    print(
        f"{test['test_id']} | "
        f"{test['name']} | "
        f"Passed={test['passed']}"
    )


print("\n" + "=" * 84)
print("        POST-INCIDENT REVIEW METRICS")
print("=" * 84)


print(
    f"Root Causes Identified: "
    f"{len(ROOT_CAUSES)}"
)

print(
    f"Control Gaps Identified: "
    f"{len(CONTROL_GAPS)}"
)

print(
    f"Corrective / Preventive Actions: "
    f"{len(ACTIONS)}"
)

print(
    f"Implemented Actions: "
    f"{implemented_actions}"
)

print(
    f"Corrective Action Completion Rate: "
    f"{corrective_action_completion_rate:.2f}%"
)

print(
    f"Detection Engineering Rules Added: "
    f"{len(DETECTION_RULES)}"
)

print(
    f"Validation Tests: "
    f"{len(VALIDATION_TESTS)}"
)

print(
    f"Validation Pass Rate: "
    f"{validation_pass_rate:.2f}%"
)

print(
    f"Control Gap Action Coverage: "
    f"{100.0 if all_control_gaps_addressed else 0.0:.2f}%"
)

print(
    f"Lessons Learned: "
    f"{len(LESSONS_LEARNED)}"
)


print("\n" + "=" * 84)
print("        LESSONS LEARNED")
print("=" * 84)


for lesson in LESSONS_LEARNED:

    print(
        f"{lesson['lesson_id']} | "
        f"{lesson['lesson']}"
    )


# ============================================================
# SECURITY CHECKS
# ============================================================

root_causes_documented = (
    len(ROOT_CAUSES) > 0
)

control_gaps_documented = (
    len(CONTROL_GAPS) > 0
)

all_actions_implemented = (
    corrective_action_completion_rate
    == 100.0
)

detection_improved = (
    HARDENED_TIMING[
        "time_to_detection_seconds"
    ]
    <
    BASELINE_TIMING[
        "time_to_detection_seconds"
    ]
)

all_validation_tests_pass = (
    validation_pass_rate
    == 100.0
)

lessons_documented = (
    len(LESSONS_LEARNED) > 0
)


pir_complete = all([
    root_causes_documented,
    control_gaps_documented,
    all_control_gaps_addressed,
    all_actions_implemented,
    detection_improved,
    all_validation_tests_pass,
    lessons_documented,
])


print("\n" + "=" * 84)
print("        POST-INCIDENT REVIEW SECURITY CHECKS")
print("=" * 84)


print(
    "Root Causes Documented:",
    root_causes_documented
)

print(
    "Control Gaps Documented:",
    control_gaps_documented
)

print(
    "All Control Gaps Have Actions:",
    all_control_gaps_addressed
)

print(
    "All Corrective Actions Implemented:",
    all_actions_implemented
)

print(
    "Detection Time Improved:",
    detection_improved
)

print(
    "All Corrective Actions Validated:",
    all_validation_tests_pass
)

print(
    "Lessons Learned Documented:",
    lessons_documented
)

print(
    "Post-Incident Review Complete:",
    pir_complete
)


# ============================================================
# EXPORT EVIDENCE
# ============================================================

REPORT = {
    "lab":
        "Day 27 Lab 15",

    "post_incident_review_id":
        PIR_ID,

    "incident_summary":
        INCIDENT_SUMMARY,

    "root_causes":
        ROOT_CAUSES,

    "control_gaps":
        CONTROL_GAPS,

    "corrective_actions":
        ACTIONS,

    "detection_engineering":
        DETECTION_RULES,

    "baseline_timing":
        BASELINE_TIMING,

    "hardened_timing":
        HARDENED_TIMING,

    "validation_tests":
        VALIDATION_TESTS,

    "lessons_learned":
        LESSONS_LEARNED,

    "metrics": {
        "root_causes":
            len(ROOT_CAUSES),

        "control_gaps":
            len(CONTROL_GAPS),

        "corrective_actions":
            len(ACTIONS),

        "corrective_action_completion_rate":
            corrective_action_completion_rate,

        "detection_rules_added":
            len(DETECTION_RULES),

        "validation_pass_rate":
            validation_pass_rate,

        "detection_time_reduction_seconds":
            detection_time_reduction,

        "detection_time_improvement_rate":
            detection_time_improvement_rate,
    },

    "security_checks": {
        "root_causes_documented":
            root_causes_documented,

        "control_gaps_documented":
            control_gaps_documented,

        "all_control_gaps_addressed":
            all_control_gaps_addressed,

        "all_actions_implemented":
            all_actions_implemented,

        "detection_improved":
            detection_improved,

        "all_validation_tests_pass":
            all_validation_tests_pass,

        "lessons_documented":
            lessons_documented,

        "post_incident_review_complete":
            pir_complete,
    },
}


OUTPUT_FILE = (
    "day27-post-incident-review-evidence.json"
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
    "The post-incident review converts forensic findings into "
    "specific corrective, preventive, and detective improvements."
)

print(
    "The incident was not treated as a single prompt-injection "
    "failure. Root-cause analysis identified failures across "
    "instruction trust, RAG admission, persistent memory, "
    "cross-session state, privileged tool control, and "
    "authorization enforcement."
)

print(
    "New correlation rules move detection earlier in the attack "
    "chain, reducing the simulated time to detection from "
    "192 seconds to 8 seconds."
)

print(
    "Corrective-action validation demonstrates that durable "
    "improvement requires both control implementation and "
    "adversarial retesting."
)


print("\nCore Principle:")

print(
    "If an AI security event cannot be observed and reconstructed, "
    "it cannot be reliably investigated or improved."
)