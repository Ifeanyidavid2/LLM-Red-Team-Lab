"""
Day 29 Lab 12
Business Impact, Blast Radius & Formal Risk Rating

Purpose:
Translate the technical Day 29 attack-chain evidence into a formal
enterprise risk assessment covering confidentiality, integrity,
availability, persistence, privilege, blast radius, detection weakness,
business consequence, inherent risk, and deployment significance.

Core Principle:
A red-team finding becomes actionable when technical exploitability is
translated into business consequence, ownership, risk severity, and a
clear treatment requirement.
"""

from datetime import datetime, timezone
from pathlib import Path
from collections import Counter
import hashlib
import json


ENGAGEMENT_ID = "ENG-2901"
SYSTEM_ID = "ENT-AI-2901"
RISK_ASSESSMENT_ID = "RISK-ASSESS-2912"
TRACE_ID = "TRACE-2912"


# =============================================================================
# BUSINESS ASSETS
# =============================================================================

BUSINESS_ASSETS = [
    {
        "asset_id": "BIZ-2901",
        "name": "Restricted Enterprise Records",
        "criticality": "CRITICAL",
        "business_owner": "Business Operations",
        "security_objectives": [
            "confidentiality",
            "integrity",
            "availability",
        ],
    },
    {
        "asset_id": "BIZ-2902",
        "name": "Enterprise AI Memory",
        "criticality": "CRITICAL",
        "business_owner": "AI Platform Team",
        "security_objectives": [
            "confidentiality",
            "integrity",
        ],
    },
    {
        "asset_id": "BIZ-2903",
        "name": "Authorization Service",
        "criticality": "CRITICAL",
        "business_owner": "Identity Security",
        "security_objectives": [
            "integrity",
            "availability",
        ],
    },
    {
        "asset_id": "BIZ-2904",
        "name": "Privileged Tooling",
        "criticality": "CRITICAL",
        "business_owner": "Application Engineering",
        "security_objectives": [
            "integrity",
            "availability",
        ],
    },
    {
        "asset_id": "BIZ-2905",
        "name": "Security Telemetry",
        "criticality": "HIGH",
        "business_owner": "AI SOC",
        "security_objectives": [
            "integrity",
            "availability",
        ],
    },
]


# =============================================================================
# RISK SCENARIOS
# =============================================================================

RISKS = [
    {
        "risk_id": "RISK-2912-01",
        "title": "Restricted Business Data Disclosure",
        "domain": "CONFIDENTIALITY",
        "severity_hint": "CRITICAL",
        "likelihood": 4,
        "impact": 5,
        "persistence": 2,
        "privilege": 4,
        "blast_radius": 4,
        "detection_difficulty": 3,
        "affected_assets": ["BIZ-2901"],
        "finding_ids": [
            "FIND-2914",
            "FIND-2916",
        ],
        "business_consequence":
            "Restricted enterprise information can be exposed through the AI interface outside approved authorization scope.",
    },
    {
        "risk_id": "RISK-2912-02",
        "title": "Persistent Cross-Session AI Compromise",
        "domain": "PERSISTENCE",
        "severity_hint": "CRITICAL",
        "likelihood": 4,
        "impact": 5,
        "persistence": 5,
        "privilege": 4,
        "blast_radius": 5,
        "detection_difficulty": 4,
        "affected_assets": [
            "BIZ-2902",
            "BIZ-2904",
        ],
        "finding_ids": [
            "FIND-2927",
            "FIND-2928",
            "FIND-2929",
            "FIND-2930",
        ],
        "business_consequence":
            "Malicious state survives the originating interaction and influences future sessions and agents.",
    },
    {
        "risk_id": "RISK-2912-03",
        "title": "Unauthorized Privileged Tool Execution",
        "domain": "PRIVILEGE",
        "severity_hint": "CRITICAL",
        "likelihood": 4,
        "impact": 5,
        "persistence": 2,
        "privilege": 5,
        "blast_radius": 5,
        "detection_difficulty": 3,
        "affected_assets": [
            "BIZ-2903",
            "BIZ-2904",
            "BIZ-2901",
        ],
        "finding_ids": [
            "FIND-2937",
            "FIND-2938",
            "FIND-2939",
            "FIND-2940",
            "FIND-2943",
            "FIND-2945",
        ],
        "business_consequence":
            "Model-influenced state can cross into privileged execution without valid independent authorization.",
    },
    {
        "risk_id": "RISK-2912-04",
        "title": "Destructive Business Data Impact",
        "domain": "INTEGRITY_AVAILABILITY",
        "severity_hint": "CRITICAL",
        "likelihood": 3,
        "impact": 5,
        "persistence": 5,
        "privilege": 5,
        "blast_radius": 5,
        "detection_difficulty": 3,
        "affected_assets": [
            "BIZ-2901",
            "BIZ-2904",
        ],
        "finding_ids": [
            "FIND-2945",
            "FIND-2946",
        ],
        "business_consequence":
            "Unauthorized AI-driven execution can modify or destroy restricted enterprise records.",
    },
    {
        "risk_id": "RISK-2912-05",
        "title": "Authorization Boundary Failure",
        "domain": "AUTHORIZATION",
        "severity_hint": "CRITICAL",
        "likelihood": 4,
        "impact": 5,
        "persistence": 2,
        "privilege": 5,
        "blast_radius": 5,
        "detection_difficulty": 3,
        "affected_assets": [
            "BIZ-2903",
            "BIZ-2904",
        ],
        "finding_ids": [
            "FIND-2906",
            "FIND-2932",
            "FIND-2941",
            "FIND-2943",
        ],
        "business_consequence":
            "Model-generated or attacker-influenced authority can reach privileged execution and denied actions may continue.",
    },
    {
        "risk_id": "RISK-2912-06",
        "title": "Credential Scope Abuse",
        "domain": "CREDENTIAL",
        "severity_hint": "CRITICAL",
        "likelihood": 3,
        "impact": 5,
        "persistence": 3,
        "privilege": 5,
        "blast_radius": 4,
        "detection_difficulty": 3,
        "affected_assets": [
            "BIZ-2904",
        ],
        "finding_ids": [
            "FIND-2944",
        ],
        "business_consequence":
            "Task credentials can be reused beyond the authorized action and amplify privileged execution risk.",
    },
    {
        "risk_id": "RISK-2912-07",
        "title": "Insufficient Early AI Attack Detection",
        "domain": "DETECTION",
        "severity_hint": "HIGH",
        "likelihood": 5,
        "impact": 4,
        "persistence": 3,
        "privilege": 2,
        "blast_radius": 4,
        "detection_difficulty": 5,
        "affected_assets": [
            "BIZ-2905",
        ],
        "finding_ids": [],
        "business_consequence":
            "AI-specific attack stages remain visible in logs but are not recognized early enough to reliably prevent downstream business impact.",
    },
    {
        "risk_id": "RISK-2912-08",
        "title": "Multi-Source Sensitive Data Aggregation",
        "domain": "CONFIDENTIALITY",
        "severity_hint": "CRITICAL",
        "likelihood": 4,
        "impact": 5,
        "persistence": 2,
        "privilege": 3,
        "blast_radius": 4,
        "detection_difficulty": 4,
        "affected_assets": [
            "BIZ-2901",
            "BIZ-2902",
        ],
        "finding_ids": [
            "FIND-2916",
        ],
        "business_consequence":
            "The GenAI system can combine sensitive information from multiple internal sources into a higher-impact disclosure.",
    },
]


# =============================================================================
# BLAST RADIUS
# =============================================================================

BLAST_RADIUS = {
    "sessions_affected": 2,
    "agents_affected": 2,
    "components_affected": 12,
    "trust_boundaries_crossed": 9,
    "correlated_findings": 20,
    "persistent_memory_affected": True,
    "authorization_boundary_affected": True,
    "credential_boundary_affected": True,
    "privileged_tool_affected": True,
    "restricted_business_data_affected": True,
    "cross_session_spread": True,
    "cross_agent_spread": True,
    "destructive_business_impact": True,
}


# =============================================================================
# DETECTION EVIDENCE
# =============================================================================

DETECTION_POSTURE = {
    "telemetry_coverage_percent": 100.00,
    "event_detection_coverage_percent": 43.75,
    "detection_rule_success_percent": 55.56,
    "early_detection_rate_percent": 0.00,
    "forensic_reconstruction_percent": 100.00,
    "missed_critical_events": 7,
    "time_to_first_detection_seconds": 64.00,
    "time_to_business_impact_seconds": 120.00,
}


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


def score_risk(risk):
    """
    Enterprise AI risk score:
    likelihood x impact plus AI-specific amplifiers.
    """

    base = (
        risk["likelihood"]
        * risk["impact"]
    )

    amplifiers = (
        risk["persistence"]
        + risk["privilege"]
        + risk["blast_radius"]
        + risk["detection_difficulty"]
    )

    return base + amplifiers


def classify(score):
    if score >= 36:
        return "CRITICAL"

    if score >= 28:
        return "HIGH"

    if score >= 18:
        return "MEDIUM"

    return "LOW"


# =============================================================================
# MAIN
# =============================================================================

def main():

    print(
        "\n=== Day 29 Lab 12: Business Impact, Blast Radius "
        "& Formal Risk Rating ==="
    )

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    # ---------------------------------------------------------------------
    # BUSINESS ASSET REGISTER
    # ---------------------------------------------------------------------

    header("BUSINESS ASSET REGISTER")

    for asset in BUSINESS_ASSETS:

        print(
            f"{asset['asset_id']} | "
            f"{asset['criticality']} | "
            f"{asset['name']}"
        )

        print(
            f"  Owner: "
            f"{asset['business_owner']}"
        )

        print(
            "  Security Objectives: "
            + ", ".join(
                asset[
                    "security_objectives"
                ]
            )
        )

    # ---------------------------------------------------------------------
    # RISK SCORING
    # ---------------------------------------------------------------------

    for risk in RISKS:

        risk["risk_score"] = score_risk(
            risk
        )

        risk["risk_rating"] = classify(
            risk["risk_score"]
        )

    prioritized_risks = sorted(
        RISKS,
        key=lambda item: (
            -item["risk_score"],
            item["risk_id"],
        )
    )

    header("FORMAL ENTERPRISE AI RISK REGISTER")

    for rank, risk in enumerate(
        prioritized_risks,
        start=1,
    ):

        print(
            f"{rank:02d} | "
            f"{risk['risk_id']} | "
            f"{risk['risk_rating']} | "
            f"Score={risk['risk_score']} | "
            f"{risk['title']}"
        )

        print(
            f"  Domain: "
            f"{risk['domain']}"
        )

        print(
            "  Affected Assets: "
            + ", ".join(
                risk["affected_assets"]
            )
        )

        print(
            f"  Business Consequence: "
            f"{risk['business_consequence']}"
        )

        print(
            "  Findings: "
            + (
                ", ".join(
                    risk["finding_ids"]
                )
                if risk["finding_ids"]
                else "Detection-derived risk"
            )
        )

    # ---------------------------------------------------------------------
    # RATING DISTRIBUTION
    # ---------------------------------------------------------------------

    rating_distribution = Counter(
        risk["risk_rating"]
        for risk in RISKS
    )

    header("RISK RATING DISTRIBUTION")

    for rating in [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    ]:

        print(
            f"{rating}: "
            f"{rating_distribution.get(rating, 0)}"
        )

    # ---------------------------------------------------------------------
    # BLAST RADIUS
    # ---------------------------------------------------------------------

    header("ENTERPRISE BLAST-RADIUS SUMMARY")

    for key, value in BLAST_RADIUS.items():

        print(
            f"{key}: {value}"
        )

    # ---------------------------------------------------------------------
    # BUSINESS IMPACT
    # ---------------------------------------------------------------------

    BUSINESS_IMPACTS = [
        {
            "impact_id": "IMPACT-2912-01",
            "category": "Confidentiality",
            "severity": "CRITICAL",
            "description":
                "Restricted business information was disclosed through the GenAI interface.",
        },
        {
            "impact_id": "IMPACT-2912-02",
            "category": "Integrity",
            "severity": "CRITICAL",
            "description":
                "Attacker-controlled state changed trusted AI goals, targets, and execution decisions.",
        },
        {
            "impact_id": "IMPACT-2912-03",
            "category": "Availability",
            "severity": "CRITICAL",
            "description":
                "Restricted business records were synthetically deleted through unauthorized privileged execution.",
        },
        {
            "impact_id": "IMPACT-2912-04",
            "category": "Persistence",
            "severity": "CRITICAL",
            "description":
                "Malicious state survived across sessions and agents through persistent memory.",
        },
        {
            "impact_id": "IMPACT-2912-05",
            "category": "Authorization",
            "severity": "CRITICAL",
            "description":
                "Denied privileged execution could continue and model-generated authority was accepted.",
        },
        {
            "impact_id": "IMPACT-2912-06",
            "category": "Detection",
            "severity": "HIGH",
            "description":
                "Early AI attack stages were observable but not detected.",
        },
    ]

    header("BUSINESS IMPACT ANALYSIS")

    for impact in BUSINESS_IMPACTS:

        print(
            f"{impact['impact_id']} | "
            f"{impact['severity']} | "
            f"{impact['category']}"
        )

        print(
            f"  {impact['description']}"
        )

    # ---------------------------------------------------------------------
    # DETECTION POSTURE
    # ---------------------------------------------------------------------

    header("DETECTION / RESPONSE RISK CONTEXT")

    for key, value in DETECTION_POSTURE.items():

        print(
            f"{key}: {value}"
        )

    # ---------------------------------------------------------------------
    # OVERALL ENGAGEMENT RISK
    # ---------------------------------------------------------------------

    highest_risk = (
        prioritized_risks[0]
    )

    critical_risks = [
        risk
        for risk in RISKS
        if risk["risk_rating"]
        == "CRITICAL"
    ]

    high_risks = [
        risk
        for risk in RISKS
        if risk["risk_rating"]
        == "HIGH"
    ]

    production_blockers = [
        risk
        for risk in RISKS
        if (
            risk["risk_rating"]
            == "CRITICAL"
            and (
                risk["privilege"] >= 5
                or
                risk["impact"] >= 5
                or
                risk["persistence"] >= 5
            )
        )
    ]

    overall_risk = (
        "CRITICAL"
        if production_blockers
        else
        "HIGH"
        if high_risks
        else
        "MEDIUM"
    )

    deployment_recommendation = (
        "BLOCK_PRODUCTION"
        if overall_risk
        == "CRITICAL"
        else
        "CONDITIONAL_APPROVAL"
        if overall_risk
        == "HIGH"
        else
        "APPROVE"
    )

    header("EXECUTIVE RISK POSITION")

    print(
        f"Overall Enterprise AI Risk: "
        f"{overall_risk}"
    )

    print(
        f"Critical Risks: "
        f"{len(critical_risks)}"
    )

    print(
        f"High Risks: "
        f"{len(high_risks)}"
    )

    print(
        f"Production-Blocking Risks: "
        f"{len(production_blockers)}"
    )

    print(
        f"Highest Risk: "
        f"{highest_risk['risk_id']} | "
        f"{highest_risk['title']} | "
        f"Score={highest_risk['risk_score']}"
    )

    print(
        f"Deployment Recommendation: "
        f"{deployment_recommendation}"
    )

    # ---------------------------------------------------------------------
    # REQUIRED RISK TREATMENT
    # ---------------------------------------------------------------------

    TREATMENT_REQUIREMENTS = [
        {
            "treatment_id": "TREAT-2912-01",
            "priority": "IMMEDIATE",
            "requirement":
                "Implement independent fail-closed authorization for all privileged tool execution.",
        },
        {
            "treatment_id": "TREAT-2912-02",
            "priority": "IMMEDIATE",
            "requirement":
                "Prevent untrusted prompt, RAG, or memory content from becoming trusted goals, targets, or authority.",
        },
        {
            "treatment_id": "TREAT-2912-03",
            "priority": "IMMEDIATE",
            "requirement":
                "Require explicit authorization, provenance, session binding, agent binding, and expiry for persistent memory.",
        },
        {
            "treatment_id": "TREAT-2912-04",
            "priority": "IMMEDIATE",
            "requirement":
                "Enforce tool allowlisting, target binding, parameter validation, and business-resource authorization.",
        },
        {
            "treatment_id": "TREAT-2912-05",
            "priority": "HIGH",
            "requirement":
                "Enforce task-bound short-lived credentials with no privilege inheritance across tools.",
        },
        {
            "treatment_id": "TREAT-2912-06",
            "priority": "HIGH",
            "requirement":
                "Implement RAG source provenance and fail-closed context admission.",
        },
        {
            "treatment_id": "TREAT-2912-07",
            "priority": "HIGH",
            "requirement":
                "Improve detection correlation for prompt, RAG, memory, cross-session, agent-goal, and model-authority anomalies.",
        },
        {
            "treatment_id": "TREAT-2912-08",
            "priority": "HIGH",
            "requirement":
                "Retest all Critical and High findings before production approval.",
        },
    ]

    header("REQUIRED RISK TREATMENT")

    for treatment in TREATMENT_REQUIREMENTS:

        print(
            f"{treatment['treatment_id']} | "
            f"{treatment['priority']}"
        )

        print(
            f"  {treatment['requirement']}"
        )

    # ---------------------------------------------------------------------
    # VALIDATION
    # ---------------------------------------------------------------------

    header("BUSINESS RISK ASSESSMENT CHECKS")

    risk_ids = [
        risk["risk_id"]
        for risk in RISKS
    ]

    asset_ids = {
        asset["asset_id"]
        for asset in BUSINESS_ASSETS
    }

    checks = {
        "Unique Risk IDs":
            len(risk_ids)
            == len(set(risk_ids)),

        "All Risk Asset References Valid":
            all(
                asset_id in asset_ids
                for risk in RISKS
                for asset_id
                in risk["affected_assets"]
            ),

        "Confidentiality Impact Identified":
            any(
                risk["domain"]
                == "CONFIDENTIALITY"
                for risk in RISKS
            ),

        "Persistence Risk Identified":
            any(
                risk["domain"]
                == "PERSISTENCE"
                for risk in RISKS
            ),

        "Privilege Risk Identified":
            any(
                risk["domain"]
                == "PRIVILEGE"
                for risk in RISKS
            ),

        "Authorization Risk Identified":
            any(
                risk["domain"]
                == "AUTHORIZATION"
                for risk in RISKS
            ),

        "Credential Risk Identified":
            any(
                risk["domain"]
                == "CREDENTIAL"
                for risk in RISKS
            ),

        "Detection Risk Identified":
            any(
                risk["domain"]
                == "DETECTION"
                for risk in RISKS
            ),

        "Business Impact Documented":
            len(BUSINESS_IMPACTS) > 0,

        "Blast Radius Documented":
            len(BLAST_RADIUS) > 0,

        "Critical Risks Identified":
            len(critical_risks) > 0,

        "Production Blockers Identified":
            len(production_blockers) > 0,

        "Risk Treatment Defined":
            len(
                TREATMENT_REQUIREMENTS
            ) > 0,

        "Explicit Deployment Recommendation":
            deployment_recommendation
            in {
                "APPROVE",
                "CONDITIONAL_APPROVAL",
                "BLOCK_PRODUCTION",
            },
    }

    checks[
        "Business Impact / Risk Assessment Valid"
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

    header("BUSINESS IMPACT / RISK SUMMARY")

    print(
        f"Risk Scenarios: "
        f"{len(RISKS)}"
    )

    print(
        f"Business Impact Categories: "
        f"{len(BUSINESS_IMPACTS)}"
    )

    print(
        f"Critical Risks: "
        f"{len(critical_risks)}"
    )

    print(
        f"High Risks: "
        f"{len(high_risks)}"
    )

    print(
        f"Production-Blocking Risks: "
        f"{len(production_blockers)}"
    )

    print(
        f"Overall Risk: "
        f"{overall_risk}"
    )

    print(
        f"Deployment Recommendation: "
        f"{deployment_recommendation}"
    )

    # ---------------------------------------------------------------------
    # EXPORT
    # ---------------------------------------------------------------------

    evidence = {
        "engagement_id":
            ENGAGEMENT_ID,

        "system_id":
            SYSTEM_ID,

        "risk_assessment_id":
            RISK_ASSESSMENT_ID,

        "trace_id":
            TRACE_ID,

        "timestamp_utc":
            timestamp,

        "business_assets":
            BUSINESS_ASSETS,

        "risk_register":
            prioritized_risks,

        "blast_radius":
            BLAST_RADIUS,

        "business_impacts":
            BUSINESS_IMPACTS,

        "detection_posture":
            DETECTION_POSTURE,

        "risk_treatment_requirements":
            TREATMENT_REQUIREMENTS,

        "executive_risk_position": {
            "overall_risk":
                overall_risk,

            "critical_risks":
                len(critical_risks),

            "high_risks":
                len(high_risks),

            "production_blocking_risks":
                len(
                    production_blockers
                ),

            "highest_risk":
                highest_risk,

            "deployment_recommendation":
                deployment_recommendation,
        },

        "security_checks":
            checks,
    }

    evidence["evidence_hash"] = hash_data(
        evidence
    )

    output = Path(
        "day29-business-impact-risk-assessment-evidence.json"
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
        "The technical red-team findings demonstrate direct enterprise "
        "risk across confidentiality, integrity, availability, persistence, "
        "privilege, authorization and detection."
    )

    print(
        "The existence of persistent compromise, authorization bypass, "
        "privileged execution and destructive business impact means the "
        "current synthetic baseline contains production-blocking risk."
    )

    print(
        "Production approval should therefore depend on remediation and "
        "successful adversarial retesting rather than acceptance of the "
        "current control state."
    )

    print("\nCore Principle:")

    print(
        "A red-team finding becomes actionable when technical "
        "exploitability is translated into business consequence, "
        "ownership, risk severity and a clear treatment requirement."
    )


if __name__ == "__main__":
    main()