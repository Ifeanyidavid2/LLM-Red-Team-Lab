"""
Day 29 Lab 1
Enterprise LLM Red-Team Security Assessment

Engagement Scope, Rules of Engagement & Assessment Baseline

Purpose:
Establish the authorization, scope, security objectives, testing boundaries,
evidence requirements, severity model, and success criteria for a synthetic
pre-production enterprise GenAI security assessment.
"""

from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json


# =============================================================================
# CONFIGURATION
# =============================================================================

ENGAGEMENT = {
    "engagement_id": "ENG-2901",
    "assessment_name": "Enterprise LLM Red-Team Security Assessment",
    "assessment_type": "Authorized Pre-Production Security Assessment",
    "environment": "synthetic-pre-production",
    "system_id": "ENT-AI-2901",
    "system_name": "Synthetic Enterprise GenAI Assistant",
    "assessor_role": "Authorized LLM / AI Red Team Security Consultant",
    "production_testing_authorized": False,
    "destructive_testing_authorized": False,
}


SYSTEM_ARCHITECTURE = [
    {
        "component_id": "COMP-2901",
        "component": "Enterprise User",
        "type": "identity",
        "trust_level": "external_authenticated",
    },
    {
        "component_id": "COMP-2902",
        "component": "AI Assistant",
        "type": "application",
        "trust_level": "application_boundary",
    },
    {
        "component_id": "COMP-2903",
        "component": "LLM Runtime",
        "type": "model",
        "trust_level": "trusted_runtime",
    },
    {
        "component_id": "COMP-2904",
        "component": "RAG Knowledge System",
        "type": "retrieval",
        "trust_level": "mixed_trust",
    },
    {
        "component_id": "COMP-2905",
        "component": "Persistent Memory",
        "type": "memory",
        "trust_level": "sensitive_persistent_state",
    },
    {
        "component_id": "COMP-2906",
        "component": "Agent Planner",
        "type": "agent",
        "trust_level": "model_influenced",
    },
    {
        "component_id": "COMP-2907",
        "component": "Tools / APIs",
        "type": "execution",
        "trust_level": "privileged_boundary",
    },
    {
        "component_id": "COMP-2908",
        "component": "Authorization Service",
        "type": "security_control",
        "trust_level": "independent_trusted_control",
    },
    {
        "component_id": "COMP-2909",
        "component": "Business Data",
        "type": "business_asset",
        "trust_level": "restricted",
    },
    {
        "component_id": "COMP-2910",
        "component": "Security Telemetry",
        "type": "observability",
        "trust_level": "trusted_security_evidence",
    },
]


AUTHORIZED_SCOPE = [
    {
        "scope_id": "SCOPE-2901",
        "asset": "AI Assistant",
        "authorized": True,
        "purpose": "Application-layer adversarial assessment",
    },
    {
        "scope_id": "SCOPE-2902",
        "asset": "LLM Runtime",
        "authorized": True,
        "purpose": "Prompt and policy security evaluation",
    },
    {
        "scope_id": "SCOPE-2903",
        "asset": "RAG Knowledge System",
        "authorized": True,
        "purpose": "Retrieval and context integrity assessment",
    },
    {
        "scope_id": "SCOPE-2904",
        "asset": "Persistent Memory",
        "authorized": True,
        "purpose": "Memory persistence and cross-session security assessment",
    },
    {
        "scope_id": "SCOPE-2905",
        "asset": "Agent Planner",
        "authorized": True,
        "purpose": "Agent goal and execution-path assessment",
    },
    {
        "scope_id": "SCOPE-2906",
        "asset": "Synthetic Tools / APIs",
        "authorized": True,
        "purpose": "Tool-use and authorization-boundary assessment",
    },
    {
        "scope_id": "SCOPE-2907",
        "asset": "Synthetic Business Data",
        "authorized": True,
        "purpose": "Controlled business-impact simulation",
    },
    {
        "scope_id": "SCOPE-2908",
        "asset": "Security Telemetry",
        "authorized": True,
        "purpose": "Detection and forensic-readiness validation",
    },
]


OUT_OF_SCOPE = [
    "Production systems",
    "Real customer information",
    "Real employee credentials",
    "Third-party systems not explicitly represented in the synthetic lab",
    "External infrastructure",
    "Real destructive operations",
    "Persistence outside the synthetic assessment environment",
    "Social engineering of real individuals",
    "Denial-of-service against real services",
]


SECURITY_OBJECTIVES = [
    {
        "objective_id": "OBJ-2901",
        "objective": "Instruction Integrity",
        "description": (
            "Prevent untrusted instructions from overriding trusted system "
            "policy or execution constraints."
        ),
    },
    {
        "objective_id": "OBJ-2902",
        "objective": "Sensitive Data Protection",
        "description": (
            "Prevent unauthorized disclosure of confidential, restricted, "
            "credential, memory, or business information."
        ),
    },
    {
        "objective_id": "OBJ-2903",
        "objective": "RAG Integrity",
        "description": (
            "Prevent poisoned or untrusted retrieval content from becoming "
            "authoritative runtime instruction."
        ),
    },
    {
        "objective_id": "OBJ-2904",
        "objective": "Persistent State Integrity",
        "description": (
            "Prevent unauthorized memory writes and cross-session malicious "
            "state propagation."
        ),
    },
    {
        "objective_id": "OBJ-2905",
        "objective": "Agent Execution Integrity",
        "description": (
            "Prevent compromised model state from changing trusted goals, "
            "targets, parameters, or privileged actions."
        ),
    },
    {
        "objective_id": "OBJ-2906",
        "objective": "Authorization Enforcement",
        "description": (
            "Ensure privileged execution requires independent, fail-closed "
            "authorization."
        ),
    },
    {
        "objective_id": "OBJ-2907",
        "objective": "Business Asset Protection",
        "description": (
            "Prevent unauthorized access, modification, or destruction of "
            "restricted business resources."
        ),
    },
    {
        "objective_id": "OBJ-2908",
        "objective": "Detection & Forensic Readiness",
        "description": (
            "Ensure security-relevant AI activity can be detected, correlated, "
            "preserved, and reconstructed."
        ),
    },
]


AUTHORIZED_TEST_CATEGORIES = [
    {
        "test_id": "TESTCAT-2901",
        "category": "prompt_injection",
        "authorized": True,
    },
    {
        "test_id": "TESTCAT-2902",
        "category": "jailbreak_policy_evasion",
        "authorized": True,
    },
    {
        "test_id": "TESTCAT-2903",
        "category": "sensitive_information_exposure",
        "authorized": True,
    },
    {
        "test_id": "TESTCAT-2904",
        "category": "rag_poisoning",
        "authorized": True,
    },
    {
        "test_id": "TESTCAT-2905",
        "category": "persistent_memory_attack",
        "authorized": True,
    },
    {
        "test_id": "TESTCAT-2906",
        "category": "agent_goal_hijacking",
        "authorized": True,
    },
    {
        "test_id": "TESTCAT-2907",
        "category": "tool_parameter_manipulation",
        "authorized": True,
    },
    {
        "test_id": "TESTCAT-2908",
        "category": "authorization_bypass_simulation",
        "authorized": True,
    },
    {
        "test_id": "TESTCAT-2909",
        "category": "multi_stage_attack_chaining",
        "authorized": True,
    },
    {
        "test_id": "TESTCAT-2910",
        "category": "detection_forensic_validation",
        "authorized": True,
    },
    {
        "test_id": "TESTCAT-2911",
        "category": "remediation_retesting",
        "authorized": True,
    },
]


RULES_OF_ENGAGEMENT = [
    {
        "rule_id": "ROE-2901",
        "rule": "Testing must remain within the synthetic pre-production environment.",
        "mandatory": True,
    },
    {
        "rule_id": "ROE-2902",
        "rule": "Only explicitly scoped synthetic assets may be targeted.",
        "mandatory": True,
    },
    {
        "rule_id": "ROE-2903",
        "rule": "No real credentials, customer data, or employee data may be used.",
        "mandatory": True,
    },
    {
        "rule_id": "ROE-2904",
        "rule": "Destructive impact must be simulated using synthetic records.",
        "mandatory": True,
    },
    {
        "rule_id": "ROE-2905",
        "rule": "Evidence must be preserved for successful and blocked attack paths.",
        "mandatory": True,
    },
    {
        "rule_id": "ROE-2906",
        "rule": "Tests must record the affected component and security objective.",
        "mandatory": True,
    },
    {
        "rule_id": "ROE-2907",
        "rule": "Testing must preserve legitimate workflow availability where practical.",
        "mandatory": True,
    },
    {
        "rule_id": "ROE-2908",
        "rule": "Remediation claims require adversarial retesting before closure.",
        "mandatory": True,
    },
]


PROHIBITED_ACTIONS = [
    {
        "prohibition_id": "PROHIBIT-2901",
        "action": "Attack real production infrastructure",
    },
    {
        "prohibition_id": "PROHIBIT-2902",
        "action": "Use stolen or real credentials",
    },
    {
        "prohibition_id": "PROHIBIT-2903",
        "action": "Access real customer or employee data",
    },
    {
        "prohibition_id": "PROHIBIT-2904",
        "action": "Perform destructive operations against real assets",
    },
    {
        "prohibition_id": "PROHIBIT-2905",
        "action": "Establish persistence outside the synthetic environment",
    },
    {
        "prohibition_id": "PROHIBIT-2906",
        "action": "Target unrelated third-party infrastructure",
    },
]


EVIDENCE_REQUIREMENTS = [
    "Stable test identifier",
    "UTC timestamp",
    "Engagement identifier",
    "Session / trace correlation where applicable",
    "Target component",
    "Attack category",
    "Test input or synthetic attack description",
    "Observed security behavior",
    "Expected security behavior",
    "Pass / fail result",
    "Security impact",
    "Evidence integrity hash",
    "Risk / severity classification",
    "Remediation status",
    "Retest status where applicable",
]


SEVERITY_MODEL = {
    "CRITICAL": {
        "score_range": "20-25",
        "description": (
            "Unauthorized privileged execution, destructive business impact, "
            "major sensitive-data compromise, or equivalent severe control failure."
        ),
    },
    "HIGH": {
        "score_range": "15-19",
        "description": (
            "Significant security-control bypass, persistent compromise, "
            "restricted-data exposure, or high-impact attack-chain enablement."
        ),
    },
    "MEDIUM": {
        "score_range": "8-14",
        "description": (
            "Meaningful security weakness requiring additional conditions "
            "or limited in business impact."
        ),
    },
    "LOW": {
        "score_range": "1-7",
        "description": (
            "Limited security impact, defense-in-depth weakness, or low-risk "
            "hardening opportunity."
        ),
    },
}


SUCCESS_CRITERIA = [
    {
        "criterion_id": "SUCCESS-2901",
        "criterion": "All in-scope AI components are identified.",
    },
    {
        "criterion_id": "SUCCESS-2902",
        "criterion": "Trust boundaries and attack surfaces are documented.",
    },
    {
        "criterion_id": "SUCCESS-2903",
        "criterion": "Major LLM attack classes are evaluated.",
    },
    {
        "criterion_id": "SUCCESS-2904",
        "criterion": "Successful attack chains are mapped to business impact.",
    },
    {
        "criterion_id": "SUCCESS-2905",
        "criterion": "Findings are assigned evidence-backed risk ratings.",
    },
    {
        "criterion_id": "SUCCESS-2906",
        "criterion": "Detection and forensic visibility are evaluated.",
    },
    {
        "criterion_id": "SUCCESS-2907",
        "criterion": "Remediation recommendations map to identified root causes.",
    },
    {
        "criterion_id": "SUCCESS-2908",
        "criterion": "High-risk remediation is adversarially retested.",
    },
    {
        "criterion_id": "SUCCESS-2909",
        "criterion": "Residual risk supports an explicit deployment decision.",
    },
]


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def canonical_json(data):
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def sha256_data(data):
    return hashlib.sha256(
        canonical_json(data).encode("utf-8")
    ).hexdigest()


def print_header(title):
    print("\n" + "=" * 88)
    print(f"        {title}")
    print("=" * 88)


# =============================================================================
# ASSESSMENT BASELINE
# =============================================================================

def build_assessment_baseline():
    timestamp = datetime.now(timezone.utc).isoformat()

    baseline = {
        "engagement_id": ENGAGEMENT["engagement_id"],
        "assessment_timestamp_utc": timestamp,
        "authorization_confirmed": True,
        "environment_confirmed_non_production": (
            ENGAGEMENT["environment"] == "synthetic-pre-production"
        ),
        "production_testing_authorized": ENGAGEMENT[
            "production_testing_authorized"
        ],
        "destructive_testing_authorized": ENGAGEMENT[
            "destructive_testing_authorized"
        ],
        "system_component_count": len(SYSTEM_ARCHITECTURE),
        "authorized_scope_count": len(AUTHORIZED_SCOPE),
        "out_of_scope_item_count": len(OUT_OF_SCOPE),
        "security_objective_count": len(SECURITY_OBJECTIVES),
        "authorized_test_category_count": len(AUTHORIZED_TEST_CATEGORIES),
        "roe_count": len(RULES_OF_ENGAGEMENT),
        "prohibited_action_count": len(PROHIBITED_ACTIONS),
        "evidence_requirement_count": len(EVIDENCE_REQUIREMENTS),
        "success_criteria_count": len(SUCCESS_CRITERIA),
    }

    baseline["baseline_hash"] = sha256_data(baseline)

    return baseline


def perform_security_checks(baseline):
    component_ids = [x["component_id"] for x in SYSTEM_ARCHITECTURE]
    scope_ids = [x["scope_id"] for x in AUTHORIZED_SCOPE]
    objective_ids = [x["objective_id"] for x in SECURITY_OBJECTIVES]
    test_ids = [x["test_id"] for x in AUTHORIZED_TEST_CATEGORIES]
    roe_ids = [x["rule_id"] for x in RULES_OF_ENGAGEMENT]

    checks = {
        "Explicit Authorization Established":
            baseline["authorization_confirmed"],

        "Synthetic Non-Production Environment":
            baseline["environment_confirmed_non_production"],

        "Production Testing Disabled":
            not baseline["production_testing_authorized"],

        "Real Destructive Testing Disabled":
            not baseline["destructive_testing_authorized"],

        "Unique Component IDs":
            len(component_ids) == len(set(component_ids)),

        "Unique Scope IDs":
            len(scope_ids) == len(set(scope_ids)),

        "Unique Security Objective IDs":
            len(objective_ids) == len(set(objective_ids)),

        "Unique Test Category IDs":
            len(test_ids) == len(set(test_ids)),

        "Unique ROE IDs":
            len(roe_ids) == len(set(roe_ids)),

        "All Scope Entries Authorized":
            all(x["authorized"] for x in AUTHORIZED_SCOPE),

        "All Test Categories Authorized":
            all(x["authorized"] for x in AUTHORIZED_TEST_CATEGORIES),

        "Mandatory ROE Defined":
            all(x["mandatory"] for x in RULES_OF_ENGAGEMENT),

        "Evidence Requirements Defined":
            len(EVIDENCE_REQUIREMENTS) > 0,

        "Severity Model Defined":
            all(
                severity in SEVERITY_MODEL
                for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            ),

        "Success Criteria Defined":
            len(SUCCESS_CRITERIA) > 0,
    }

    checks["Assessment Baseline Valid"] = all(checks.values())

    return checks


# =============================================================================
# OUTPUT
# =============================================================================

def main():
    print(
        "\n=== Day 29 Lab 1: Engagement Scope, Rules of Engagement "
        "& Assessment Baseline ==="
    )

    baseline = build_assessment_baseline()
    checks = perform_security_checks(baseline)

    print_header("ENGAGEMENT IDENTIFICATION")

    for key, value in ENGAGEMENT.items():
        print(f"{key}: {value}")

    print_header("ENTERPRISE GENAI SYSTEM ARCHITECTURE")

    for item in SYSTEM_ARCHITECTURE:
        print(
            f"{item['component_id']} | "
            f"{item['component']} | "
            f"{item['type']} | "
            f"Trust={item['trust_level']}"
        )

    print_header("AUTHORIZED SCOPE")

    for item in AUTHORIZED_SCOPE:
        print(
            f"{item['scope_id']} | {item['asset']} | "
            f"Authorized={item['authorized']}"
        )
        print(f"  Purpose: {item['purpose']}")

    print_header("OUT-OF-SCOPE ASSETS / ACTIVITIES")

    for item in OUT_OF_SCOPE:
        print(f"- {item}")

    print_header("SECURITY OBJECTIVES")

    for item in SECURITY_OBJECTIVES:
        print(
            f"{item['objective_id']} | "
            f"{item['objective']}"
        )
        print(f"  {item['description']}")

    print_header("AUTHORIZED TEST CATEGORIES")

    for item in AUTHORIZED_TEST_CATEGORIES:
        print(
            f"{item['test_id']} | "
            f"{item['category']} | "
            f"Authorized={item['authorized']}"
        )

    print_header("RULES OF ENGAGEMENT")

    for item in RULES_OF_ENGAGEMENT:
        print(
            f"{item['rule_id']} | "
            f"Mandatory={item['mandatory']}"
        )
        print(f"  {item['rule']}")

    print_header("PROHIBITED ACTIONS")

    for item in PROHIBITED_ACTIONS:
        print(
            f"{item['prohibition_id']} | "
            f"{item['action']}"
        )

    print_header("EVIDENCE REQUIREMENTS")

    for index, requirement in enumerate(
        EVIDENCE_REQUIREMENTS,
        start=1,
    ):
        print(f"{index:02d}. {requirement}")

    print_header("RISK / SEVERITY MODEL")

    for severity, details in SEVERITY_MODEL.items():
        print(
            f"{severity} | Score={details['score_range']}"
        )
        print(f"  {details['description']}")

    print_header("ASSESSMENT SUCCESS CRITERIA")

    for item in SUCCESS_CRITERIA:
        print(
            f"{item['criterion_id']} | "
            f"{item['criterion']}"
        )

    print_header("ASSESSMENT BASELINE")

    for key, value in baseline.items():
        print(f"{key}: {value}")

    print_header("BASELINE SECURITY CHECKS")

    for check, result in checks.items():
        print(f"{check}: {result}")

    evidence_package = {
        "engagement": ENGAGEMENT,
        "system_architecture": SYSTEM_ARCHITECTURE,
        "authorized_scope": AUTHORIZED_SCOPE,
        "out_of_scope": OUT_OF_SCOPE,
        "security_objectives": SECURITY_OBJECTIVES,
        "authorized_test_categories": AUTHORIZED_TEST_CATEGORIES,
        "rules_of_engagement": RULES_OF_ENGAGEMENT,
        "prohibited_actions": PROHIBITED_ACTIONS,
        "evidence_requirements": EVIDENCE_REQUIREMENTS,
        "severity_model": SEVERITY_MODEL,
        "success_criteria": SUCCESS_CRITERIA,
        "assessment_baseline": baseline,
        "security_checks": checks,
    }

    evidence_package["evidence_package_hash"] = sha256_data(
        evidence_package
    )

    evidence_path = Path(
        "day29-engagement-scope-assessment-baseline-evidence.json"
    )

    evidence_path.write_text(
        json.dumps(
            evidence_package,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print("\nEvidence written to:")
    print(evidence_path)

    print("\nSecurity Interpretation:")
    print(
        "The Day 29 capstone begins with explicit authorization, "
        "defined scope, Rules of Engagement, prohibited actions, "
        "security objectives, evidence requirements and assessment "
        "success criteria."
    )
    print(
        "This establishes a defensible professional baseline before "
        "any adversarial testing begins."
    )
    print(
        "The assessment is restricted to a synthetic pre-production "
        "enterprise GenAI environment so later attack simulation can "
        "demonstrate realistic security impact without targeting real "
        "systems, identities or business data."
    )

    print("\nCore Principle:")
    print(
        "A professional LLM red-team assessment must demonstrate not "
        "only whether an attack succeeds, but how it succeeds, what "
        "business assets are affected, why controls failed, how the "
        "risk should be remediated, and whether the remediation "
        "withstands adversarial retesting."
    )


if __name__ == "__main__":
    main()