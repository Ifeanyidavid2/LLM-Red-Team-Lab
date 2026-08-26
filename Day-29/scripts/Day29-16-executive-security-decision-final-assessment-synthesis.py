"""
Day 29 Lab 16
Executive Security Decision & Final Assessment Synthesis

Purpose:
Consolidate the complete Day 29 enterprise LLM red-team assessment into
a final executive security decision.

The lab reconciles:
- original attack success;
- business impact;
- consolidated findings;
- remediation implementation;
- adversarial retesting;
- residual risk;
- legitimate utility;
- detection improvements;
- operational monitoring requirements;
- deployment conditions.

Core Principle:
Security approval should be based on demonstrated control effectiveness,
residual risk and explicit deployment conditions—not simply on whether
remediation work was completed.
"""

from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json


ENGAGEMENT_ID = "ENG-2901"
SYSTEM_ID = "ENT-AI-2901"
ASSESSMENT_ID = "FINAL-ASSESS-2916"
TRACE_ID = "TRACE-2916"


# =============================================================================
# ENGAGEMENT CONTEXT
# =============================================================================

ENGAGEMENT = {
    "engagement_id": ENGAGEMENT_ID,
    "system_id": SYSTEM_ID,

    "system_name":
        "Synthetic Enterprise GenAI Assistant",

    "assessment_type":
        "Authorized Pre-Production Enterprise LLM Red-Team Security Assessment",

    "business_function":
        "Enterprise knowledge retrieval and authorized workflow automation",

    "assessment_stage":
        "final_security_decision",
}


# =============================================================================
# BASELINE SECURITY POSTURE
# =============================================================================

BASELINE_POSTURE = {
    "overall_risk":
        "CRITICAL",

    "deployment_recommendation":
        "BLOCK_PRODUCTION",

    "attack_chain_successful":
        True,

    "material_findings":
        8,

    "critical_findings":
        6,

    "high_findings":
        2,

    "persistent_compromise":
        True,

    "authorization_bypass":
        True,

    "credential_scope_abuse":
        True,

    "restricted_data_exposure":
        True,

    "destructive_business_impact":
        True,

    "early_detection_rate_percent":
        0.00,

    "event_detection_coverage_percent":
        43.75,

    "time_to_detection_seconds":
        64.00,
}


# =============================================================================
# HARDENED / RETESTED SECURITY POSTURE
# =============================================================================

HARDENED_POSTURE = {
    "material_findings_closed":
        8,

    "material_findings_total":
        8,

    "adversarial_retests":
        33,

    "passed_retests":
        33,

    "failed_retests":
        0,

    "retest_pass_rate_percent":
        100.00,

    "attack_chain_blocked":
        True,

    "legitimate_workflow_completion_percent":
        100.00,

    "false_block_rate_percent":
        0.00,

    "critical_residual_risks":
        0,

    "high_residual_risks":
        0,

    "highest_residual_risk_score":
        5,

    "early_detection_rate_percent":
        100.00,

    "event_detection_coverage_percent":
        100.00,

    "time_to_detection_seconds":
        8.00,

    "adversarial_retest_gate_passed":
        True,
}


# =============================================================================
# MATERIAL FINDING CLOSURE
# =============================================================================

MATERIAL_FINDINGS = [
    {
        "finding_id": "CF-2901",
        "title":
            "Untrusted Instructions Can Alter Trusted AI Tasks and Targets",
        "baseline_severity": "CRITICAL",
        "retest_status": "CLOSED",
    },
    {
        "finding_id": "CF-2902",
        "title":
            "RAG Trust Boundary Permits Poisoned Context and Indirect Prompt Injection",
        "baseline_severity": "CRITICAL",
        "retest_status": "CLOSED",
    },
    {
        "finding_id": "CF-2903",
        "title":
            "Persistent AI Memory Enables Cross-Session and Cross-Agent Compromise",
        "baseline_severity": "CRITICAL",
        "retest_status": "CLOSED",
    },
    {
        "finding_id": "CF-2904",
        "title":
            "Agent and Tool Boundaries Permit Privileged Execution Manipulation",
        "baseline_severity": "CRITICAL",
        "retest_status": "CLOSED",
    },
    {
        "finding_id": "CF-2905",
        "title":
            "Authorization Enforcement Fails Closed Inconsistently",
        "baseline_severity": "CRITICAL",
        "retest_status": "CLOSED",
    },
    {
        "finding_id": "CF-2906",
        "title":
            "Task Credentials Are Not Sufficiently Scoped to Authorized Operations",
        "baseline_severity": "HIGH",
        "retest_status": "CLOSED",
    },
    {
        "finding_id": "CF-2907",
        "title":
            "Sensitive Model-Visible Data Can Be Exposed or Aggregated",
        "baseline_severity": "CRITICAL",
        "retest_status": "CLOSED",
    },
    {
        "finding_id": "CF-2908",
        "title":
            "AI Detection Engineering Misses Early Attack Stages",
        "baseline_severity": "HIGH",
        "retest_status": "CLOSED",
    },
]


# =============================================================================
# RESIDUAL RISK POSITION
# =============================================================================

RESIDUAL_RISKS = [
    {
        "risk_id": "RESIDUAL-2915-01",
        "title": "Prompt / Instruction Manipulation",
        "rating": "LOW",
        "score": 4,
    },
    {
        "risk_id": "RESIDUAL-2915-02",
        "title": "RAG Poisoning",
        "rating": "LOW",
        "score": 4,
    },
    {
        "risk_id": "RESIDUAL-2915-03",
        "title": "Persistent Memory Compromise",
        "rating": "LOW",
        "score": 5,
    },
    {
        "risk_id": "RESIDUAL-2915-04",
        "title": "Agent / Tool Abuse",
        "rating": "LOW",
        "score": 5,
    },
    {
        "risk_id": "RESIDUAL-2915-05",
        "title": "Authorization Bypass",
        "rating": "LOW",
        "score": 5,
    },
    {
        "risk_id": "RESIDUAL-2915-06",
        "title": "Credential Scope Abuse",
        "rating": "LOW",
        "score": 4,
    },
    {
        "risk_id": "RESIDUAL-2915-07",
        "title": "Sensitive Data Exposure",
        "rating": "LOW",
        "score": 5,
    },
    {
        "risk_id": "RESIDUAL-2915-08",
        "title": "Late AI Attack Detection",
        "rating": "LOW",
        "score": 3,
    },
]


# =============================================================================
# DEPLOYMENT CONDITIONS
# =============================================================================

DEPLOYMENT_CONDITIONS = [
    {
        "condition_id": "COND-2916-01",
        "priority": "MANDATORY",
        "condition":
            "Keep independent fail-closed authorization enabled for every privileged tool execution.",
        "owner":
            "Identity Security",
    },
    {
        "condition_id": "COND-2916-02",
        "priority": "MANDATORY",
        "condition":
            "Maintain RAG provenance validation, indirect prompt-injection scanning and fail-closed context admission.",
        "owner":
            "RAG Platform Team",
    },
    {
        "condition_id": "COND-2916-03",
        "priority": "MANDATORY",
        "condition":
            "Require authorization, provenance, session/agent binding and expiry for persistent memory.",
        "owner":
            "AI Platform Team",
    },
    {
        "condition_id": "COND-2916-04",
        "priority": "MANDATORY",
        "condition":
            "Maintain trusted task/goal/target binding and strict tool parameter validation.",
        "owner":
            "Agent Security Team",
    },
    {
        "condition_id": "COND-2916-05",
        "priority": "MANDATORY",
        "condition":
            "Use short-lived task-bound and target-bound credentials.",
        "owner":
            "Platform Identity Team",
    },
    {
        "condition_id": "COND-2916-06",
        "priority": "MANDATORY",
        "condition":
            "Maintain independent data authorization, sensitive-context minimization and output DLP.",
        "owner":
            "Data Security",
    },
    {
        "condition_id": "COND-2916-07",
        "priority": "MANDATORY",
        "condition":
            "Operate prompt/RAG/memory/agent/tool correlation rules continuously in production.",
        "owner":
            "AI SOC",
    },
    {
        "condition_id": "COND-2916-08",
        "priority": "MANDATORY",
        "condition":
            "Preserve tamper-evident AI security telemetry sufficient for incident reconstruction.",
        "owner":
            "AI SOC",
    },
    {
        "condition_id": "COND-2916-09",
        "priority": "MANDATORY",
        "condition":
            "Run adversarial regression tests after security-sensitive model, prompt, RAG, memory, agent, tool, policy or authorization changes.",
        "owner":
            "AI Security Engineering",
    },
    {
        "condition_id": "COND-2916-10",
        "priority": "GOVERNANCE",
        "condition":
            "Review residual AI risk after deployment and formally reassess if new Critical or High findings emerge.",
        "owner":
            "AI Risk Governance",
    },
]


# =============================================================================
# POST-DEPLOYMENT MONITORING
# =============================================================================

MONITORING_REQUIREMENTS = [
    {
        "monitor_id": "MON-2916-01",
        "metric":
            "Prompt / indirect-injection alerts",
        "threshold":
            "Investigate High/Critical correlated events",
    },
    {
        "monitor_id": "MON-2916-02",
        "metric":
            "Unauthorized memory write attempts",
        "threshold":
            "Zero successful unauthorized writes",
    },
    {
        "monitor_id": "MON-2916-03",
        "metric":
            "Cross-session / cross-agent memory anomalies",
        "threshold":
            "Zero unauthorized propagation",
    },
    {
        "monitor_id": "MON-2916-04",
        "metric":
            "Privileged tool requests",
        "threshold":
            "100% independently authorized",
    },
    {
        "monitor_id": "MON-2916-05",
        "metric":
            "Execution after authorization denial",
        "threshold":
            "Zero events",
    },
    {
        "monitor_id": "MON-2916-06",
        "metric":
            "Credential scope violations",
        "threshold":
            "Zero successful scope violations",
    },
    {
        "monitor_id": "MON-2916-07",
        "metric":
            "Restricted-data DLP violations",
        "threshold":
            "Zero confirmed unauthorized disclosures",
    },
    {
        "monitor_id": "MON-2916-08",
        "metric":
            "Time to AI security detection",
        "threshold":
            "Maintain early detection before privileged execution",
    },
]


# =============================================================================
# DECISION CRITERIA
# =============================================================================

DECISION_CRITERIA = [
    {
        "criterion_id": "DEC-2916-01",
        "name": "Critical Findings Closed",
        "required": True,
        "passed": True,
    },
    {
        "criterion_id": "DEC-2916-02",
        "name": "High Findings Closed",
        "required": True,
        "passed": True,
    },
    {
        "criterion_id": "DEC-2916-03",
        "name": "All Adversarial Retests Passed",
        "required": True,
        "passed": True,
    },
    {
        "criterion_id": "DEC-2916-04",
        "name": "End-to-End Attack Chain Blocked",
        "required": True,
        "passed": True,
    },
    {
        "criterion_id": "DEC-2916-05",
        "name": "Legitimate Utility Preserved",
        "required": True,
        "passed": True,
    },
    {
        "criterion_id": "DEC-2916-06",
        "name": "No Critical Residual Risk",
        "required": True,
        "passed": True,
    },
    {
        "criterion_id": "DEC-2916-07",
        "name": "No High Residual Risk",
        "required": True,
        "passed": True,
    },
    {
        "criterion_id": "DEC-2916-08",
        "name": "Early Detection Validated",
        "required": True,
        "passed": True,
    },
    {
        "criterion_id": "DEC-2916-09",
        "name": "Operational Monitoring Required",
        "required": True,
        "passed": True,
    },
    {
        "criterion_id": "DEC-2916-10",
        "name": "Post-Change Adversarial Regression Required",
        "required": True,
        "passed": True,
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
    print("\n" + "=" * 104)
    print(f"        {title}")
    print("=" * 104)


# =============================================================================
# MAIN
# =============================================================================

def main():

    print(
        "\n=== Day 29 Lab 16: Executive Security Decision "
        "& Final Assessment Synthesis ==="
    )

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    # ---------------------------------------------------------------------
    # ENGAGEMENT
    # ---------------------------------------------------------------------

    header("ENGAGEMENT SUMMARY")

    for key, value in ENGAGEMENT.items():
        print(
            f"{key}: {value}"
        )

    # ---------------------------------------------------------------------
    # BASELINE
    # ---------------------------------------------------------------------

    header("BASELINE SECURITY POSTURE")

    for key, value in BASELINE_POSTURE.items():
        print(
            f"{key}: {value}"
        )

    # ---------------------------------------------------------------------
    # HARDENED POSTURE
    # ---------------------------------------------------------------------

    header("HARDENED / RETESTED SECURITY POSTURE")

    for key, value in HARDENED_POSTURE.items():
        print(
            f"{key}: {value}"
        )

    # ---------------------------------------------------------------------
    # FINDINGS
    # ---------------------------------------------------------------------

    header("MATERIAL FINDING CLOSURE")

    for finding in MATERIAL_FINDINGS:

        print(
            f"{finding['finding_id']} | "
            f"{finding['baseline_severity']} | "
            f"{finding['retest_status']} | "
            f"{finding['title']}"
        )

    closed_findings = [
        finding
        for finding in MATERIAL_FINDINGS
        if finding["retest_status"]
        == "CLOSED"
    ]

    open_findings = [
        finding
        for finding in MATERIAL_FINDINGS
        if finding["retest_status"]
        != "CLOSED"
    ]

    # ---------------------------------------------------------------------
    # RESIDUAL RISK
    # ---------------------------------------------------------------------

    header("FINAL RESIDUAL RISK POSITION")

    for risk in RESIDUAL_RISKS:

        print(
            f"{risk['risk_id']} | "
            f"{risk['rating']} | "
            f"Score={risk['score']} | "
            f"{risk['title']}"
        )

    critical_residual = [
        risk
        for risk in RESIDUAL_RISKS
        if risk["rating"]
        == "CRITICAL"
    ]

    high_residual = [
        risk
        for risk in RESIDUAL_RISKS
        if risk["rating"]
        == "HIGH"
    ]

    medium_residual = [
        risk
        for risk in RESIDUAL_RISKS
        if risk["rating"]
        == "MEDIUM"
    ]

    low_residual = [
        risk
        for risk in RESIDUAL_RISKS
        if risk["rating"]
        == "LOW"
    ]

    # ---------------------------------------------------------------------
    # SECURITY DECISION CRITERIA
    # ---------------------------------------------------------------------

    header("EXECUTIVE SECURITY DECISION CRITERIA")

    for criterion in DECISION_CRITERIA:

        print(
            f"{criterion['criterion_id']} | "
            f"{'PASS' if criterion['passed'] else 'FAIL'} | "
            f"{criterion['name']}"
        )

    required_criteria = [
        criterion
        for criterion in DECISION_CRITERIA
        if criterion["required"]
    ]

    passed_criteria = [
        criterion
        for criterion in required_criteria
        if criterion["passed"]
    ]

    all_required_criteria_pass = all(
        criterion["passed"]
        for criterion in required_criteria
    )

    # ---------------------------------------------------------------------
    # FINAL DECISION
    # ---------------------------------------------------------------------

    if (
        open_findings
        or critical_residual
        or high_residual
        or not HARDENED_POSTURE[
            "attack_chain_blocked"
        ]
        or not all_required_criteria_pass
    ):
        final_decision = (
            "BLOCK_PRODUCTION"
        )

    elif (
        all_required_criteria_pass
        and not critical_residual
        and not high_residual
    ):
        final_decision = (
            "CONDITIONAL_APPROVAL"
        )

    else:
        final_decision = (
            "REASSESS"
        )

    # ---------------------------------------------------------------------
    # DECISION RATIONALE
    # ---------------------------------------------------------------------

    DECISION_RATIONALE = [
        "The original assessment demonstrated a successful multi-stage enterprise LLM attack chain.",
        "The attack reached persistent memory, crossed session and agent boundaries, bypassed authorization and produced synthetic business impact.",
        "Eight material security findings were identified and remediated.",
        "All 33 adversarial retests subsequently passed.",
        "All eight material findings were closed under retest.",
        "The complete original end-to-end attack chain was blocked.",
        "Legitimate enterprise workflows remained functional with zero measured false blocking.",
        "Early AI attack detection improved materially.",
        "No Critical or High residual risks remain in the synthetic retest model.",
        "Ongoing monitoring and adversarial regression are still required because GenAI behavior, prompts, retrieval sources, models, tools and integrations can change over time.",
    ]

    header("EXECUTIVE SECURITY DECISION")

    print(
        f"Original Deployment Decision: "
        f"{BASELINE_POSTURE['deployment_recommendation']}"
    )

    print(
        f"Final Security Decision: "
        f"{final_decision}"
    )

    print(
        f"Required Decision Criteria Passed: "
        f"{len(passed_criteria)} / "
        f"{len(required_criteria)}"
    )

    print(
        f"Material Findings Closed: "
        f"{len(closed_findings)} / "
        f"{len(MATERIAL_FINDINGS)}"
    )

    print(
        f"Critical Residual Risks: "
        f"{len(critical_residual)}"
    )

    print(
        f"High Residual Risks: "
        f"{len(high_residual)}"
    )

    print(
        f"Attack Chain Blocked: "
        f"{HARDENED_POSTURE['attack_chain_blocked']}"
    )

    print(
        f"Adversarial Retest Pass Rate: "
        f"{HARDENED_POSTURE['retest_pass_rate_percent']:.2f}%"
    )

    print(
        f"Legitimate Utility: "
        f"{HARDENED_POSTURE['legitimate_workflow_completion_percent']:.2f}%"
    )

    # ---------------------------------------------------------------------
    # RATIONALE
    # ---------------------------------------------------------------------

    header("DECISION RATIONALE")

    for index, rationale in enumerate(
        DECISION_RATIONALE,
        start=1,
    ):

        print(
            f"{index:02d}. "
            f"{rationale}"
        )

    # ---------------------------------------------------------------------
    # DEPLOYMENT CONDITIONS
    # ---------------------------------------------------------------------

    header("CONDITIONS OF SECURITY APPROVAL")

    for condition in DEPLOYMENT_CONDITIONS:

        print(
            f"{condition['condition_id']} | "
            f"{condition['priority']} | "
            f"{condition['owner']}"
        )

        print(
            f"  {condition['condition']}"
        )

    # ---------------------------------------------------------------------
    # MONITORING
    # ---------------------------------------------------------------------

    header("POST-DEPLOYMENT SECURITY MONITORING")

    for requirement in MONITORING_REQUIREMENTS:

        print(
            f"{requirement['monitor_id']} | "
            f"{requirement['metric']}"
        )

        print(
            f"  Threshold: "
            f"{requirement['threshold']}"
        )

    # ---------------------------------------------------------------------
    # SECURITY POSTURE COMPARISON
    # ---------------------------------------------------------------------

    header("BASELINE VS FINAL SECURITY POSTURE")

    comparisons = [
        (
            "Attack Chain Successful",
            BASELINE_POSTURE[
                "attack_chain_successful"
            ],
            not HARDENED_POSTURE[
                "attack_chain_blocked"
            ],
        ),
        (
            "Critical Findings",
            BASELINE_POSTURE[
                "critical_findings"
            ],
            0,
        ),
        (
            "High Findings",
            BASELINE_POSTURE[
                "high_findings"
            ],
            0,
        ),
        (
            "Early Detection Rate",
            BASELINE_POSTURE[
                "early_detection_rate_percent"
            ],
            HARDENED_POSTURE[
                "early_detection_rate_percent"
            ],
        ),
        (
            "Event Detection Coverage",
            BASELINE_POSTURE[
                "event_detection_coverage_percent"
            ],
            HARDENED_POSTURE[
                "event_detection_coverage_percent"
            ],
        ),
        (
            "Time to Detection",
            BASELINE_POSTURE[
                "time_to_detection_seconds"
            ],
            HARDENED_POSTURE[
                "time_to_detection_seconds"
            ],
        ),
    ]

    for metric, baseline, hardened in comparisons:

        print(
            f"{metric}: "
            f"Baseline={baseline} | "
            f"Final={hardened}"
        )

    # ---------------------------------------------------------------------
    # VALIDATION
    # ---------------------------------------------------------------------

    checks = {
        "All Material Findings Closed":
            len(open_findings) == 0,

        "All Adversarial Retests Passed":
            HARDENED_POSTURE[
                "failed_retests"
            ] == 0,

        "End-to-End Attack Chain Blocked":
            HARDENED_POSTURE[
                "attack_chain_blocked"
            ],

        "Legitimate Utility Preserved":
            HARDENED_POSTURE[
                "legitimate_workflow_completion_percent"
            ] == 100.0,

        "No Critical Residual Risk":
            len(
                critical_residual
            ) == 0,

        "No High Residual Risk":
            len(
                high_residual
            ) == 0,

        "Detection Improved":
            HARDENED_POSTURE[
                "time_to_detection_seconds"
            ]
            <
            BASELINE_POSTURE[
                "time_to_detection_seconds"
            ],

        "Deployment Conditions Defined":
            len(
                DEPLOYMENT_CONDITIONS
            ) > 0,

        "Post-Deployment Monitoring Defined":
            len(
                MONITORING_REQUIREMENTS
            ) > 0,

        "All Required Decision Criteria Pass":
            all_required_criteria_pass,

        "Final Decision Is Conditional Approval":
            final_decision
            == "CONDITIONAL_APPROVAL",
    }

    checks[
        "Executive Security Decision Valid"
    ] = all(
        checks.values()
    )

    header("FINAL ASSESSMENT SECURITY CHECKS")

    for check, result in checks.items():

        print(
            f"{check}: {result}"
        )

    # ---------------------------------------------------------------------
    # FINAL EXECUTIVE SUMMARY
    # ---------------------------------------------------------------------

    header("FINAL EXECUTIVE SECURITY SUMMARY")

    print(
        "Assessment Conclusion:"
    )

    print(
        "The baseline enterprise GenAI application demonstrated "
        "Critical security weaknesses capable of chaining prompt and "
        "retrieval manipulation into persistent memory compromise, "
        "cross-session propagation, agent/tool abuse, authorization "
        "bypass, credential misuse, sensitive-data exposure and "
        "destructive synthetic business impact."
    )

    print()

    print(
        "Following implementation of hardened architectural controls, "
        "all material findings passed adversarial retesting, the "
        "previously successful attack chain was blocked and legitimate "
        "business functionality remained available."
    )

    print()

    print(
        "Residual risk is Low in the modeled environment. Production "
        "deployment may therefore proceed under CONDITIONAL APPROVAL, "
        "subject to continued operation of the documented security "
        "controls, monitoring requirements and adversarial regression "
        "testing."
    )

    # ---------------------------------------------------------------------
    # EXPORT
    # ---------------------------------------------------------------------

    evidence = {
        "engagement":
            ENGAGEMENT,

        "assessment_id":
            ASSESSMENT_ID,

        "trace_id":
            TRACE_ID,

        "timestamp_utc":
            timestamp,

        "baseline_posture":
            BASELINE_POSTURE,

        "hardened_posture":
            HARDENED_POSTURE,

        "material_findings":
            MATERIAL_FINDINGS,

        "residual_risk_register":
            RESIDUAL_RISKS,

        "decision_criteria":
            DECISION_CRITERIA,

        "deployment_conditions":
            DEPLOYMENT_CONDITIONS,

        "monitoring_requirements":
            MONITORING_REQUIREMENTS,

        "decision_rationale":
            DECISION_RATIONALE,

        "final_security_decision": {
            "decision":
                final_decision,

            "original_decision":
                BASELINE_POSTURE[
                    "deployment_recommendation"
                ],

            "material_findings_closed":
                len(
                    closed_findings
                ),

            "material_findings_total":
                len(
                    MATERIAL_FINDINGS
                ),

            "critical_residual_risks":
                len(
                    critical_residual
                ),

            "high_residual_risks":
                len(
                    high_residual
                ),

            "medium_residual_risks":
                len(
                    medium_residual
                ),

            "low_residual_risks":
                len(
                    low_residual
                ),

            "required_criteria_passed":
                len(
                    passed_criteria
                ),

            "required_criteria_total":
                len(
                    required_criteria
                ),
        },

        "security_checks":
            checks,
    }

    evidence["evidence_hash"] = hash_data(
        evidence
    )

    output = Path(
        "day29-executive-security-decision-final-assessment-evidence.json"
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
        "The final security decision reconciles technical exploitation, "
        "business impact, remediation, adversarial retesting and residual "
        "risk into an executive deployment recommendation."
    )

    print(
        "The original production block is removed only because the "
        "demonstrated attack paths have been retested successfully and "
        "no Critical or High residual risks remain in the modeled "
        "environment."
    )

    print(
        "Conditional approval preserves governance discipline by "
        "requiring the hardened controls, monitoring and adversarial "
        "regression program to remain active after deployment."
    )

    print("\nCore Principle:")

    print(
        "Security approval should be based on demonstrated control "
        "effectiveness, residual risk and explicit deployment conditions—not "
        "simply on whether remediation work was completed."
    )


if __name__ == "__main__":
    main()