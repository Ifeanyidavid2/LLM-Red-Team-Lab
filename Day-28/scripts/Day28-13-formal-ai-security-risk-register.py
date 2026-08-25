"""
Day 28 Lab 13
Formal AI Security Risk Register

Purpose:
Translate Day 28 AI threat-model findings into formal business-facing
risk records with ownership, affected assets, risk treatment,
control ownership, target state, residual risk and deployment decision.

Core Principle:
AI security should be designed from identified threats and trust
boundaries, not added only after vulnerabilities are discovered.
"""

import json
from collections import Counter


print(
    "\n=== Day 28 Lab 13: "
    "Formal AI Security Risk Register ===\n"
)


# ============================================================
# RISK REGISTER
# ============================================================

RISK_REGISTER = [
    {
        "risk_id": "RISK-2801",
        "name": "Direct Prompt Injection",
        "domain": "PROMPT",
        "owner": "AI Security Engineering",
        "affected_assets": [
            "User Prompt",
            "System Prompt",
            "LLM Runtime",
        ],
        "business_consequence":
            "Untrusted instructions may override intended task behavior.",
        "inherent_score": 27,
        "inherent_rating": "CRITICAL",
        "treatment": "MITIGATE",
        "required_controls": [
            "Instruction trust separation",
            "Prompt injection detection",
            "Policy integrity enforcement",
        ],
        "control_owner": "AI Platform Team",
        "target_residual_score": 8,
        "target_residual_rating": "MEDIUM",
        "risk_acceptance_allowed": True,
    },

    {
        "risk_id": "RISK-2802",
        "name": "Indirect RAG Prompt Injection",
        "domain": "RAG",
        "owner": "RAG Platform Owner",
        "affected_assets": [
            "RAG Knowledge Store",
            "Retrieved Documents",
            "LLM Runtime",
        ],
        "business_consequence":
            "Retrieved content may manipulate runtime behavior.",
        "inherent_score": 37,
        "inherent_rating": "CRITICAL",
        "treatment": "MITIGATE",
        "required_controls": [
            "RAG provenance validation",
            "Indirect prompt-injection scanning",
            "Context admission gateway",
        ],
        "control_owner": "RAG Security Team",
        "target_residual_score": 8,
        "target_residual_rating": "MEDIUM",
        "risk_acceptance_allowed": True,
    },

    {
        "risk_id": "RISK-2803",
        "name": "RAG Source Poisoning",
        "domain": "RAG",
        "owner": "Knowledge Platform Owner",
        "affected_assets": [
            "Knowledge Sources",
            "RAG Store",
            "Retrieved Context",
        ],
        "business_consequence":
            "Malicious source content may persist and influence many sessions.",
        "inherent_score": 33,
        "inherent_rating": "CRITICAL",
        "treatment": "MITIGATE",
        "required_controls": [
            "Trusted source allowlisting",
            "Document integrity validation",
            "Source provenance metadata",
        ],
        "control_owner": "RAG Platform Team",
        "target_residual_score": 8,
        "target_residual_rating": "MEDIUM",
        "risk_acceptance_allowed": True,
    },

    {
        "risk_id": "RISK-2804",
        "name": "Unsafe Context Admission",
        "domain": "RAG",
        "owner": "AI Runtime Owner",
        "affected_assets": [
            "Retrieved Context",
            "LLM Runtime",
        ],
        "business_consequence":
            "Untrusted content may enter the runtime without validation.",
        "inherent_score": 32,
        "inherent_rating": "CRITICAL",
        "treatment": "MITIGATE",
        "required_controls": [
            "Context trust classification",
            "Fail-closed context admission",
            "Retrieved content treated as data",
        ],
        "control_owner": "AI Security Engineering",
        "target_residual_score": 7,
        "target_residual_rating": "MEDIUM",
        "risk_acceptance_allowed": True,
    },

    {
        "risk_id": "RISK-2805",
        "name": "Persistent Memory Poisoning",
        "domain": "MEMORY",
        "owner": "AI Platform Owner",
        "affected_assets": [
            "Persistent AI Memory",
            "Future Sessions",
            "Agents",
        ],
        "business_consequence":
            "Malicious state may survive sessions and influence future actions.",
        "inherent_score": 42,
        "inherent_rating": "CRITICAL",
        "treatment": "MITIGATE",
        "required_controls": [
            "Explicit memory-write authorization",
            "Memory provenance",
            "Memory integrity validation",
            "Expiry and revocation",
        ],
        "control_owner": "AI Platform Team",
        "target_residual_score": 5,
        "target_residual_rating": "LOW",
        "risk_acceptance_allowed": True,
    },

    {
        "risk_id": "RISK-2806",
        "name": "Cross-Session Memory Activation",
        "domain": "MEMORY",
        "owner": "AI Platform Owner",
        "affected_assets": [
            "Persistent Memory",
            "User Sessions",
        ],
        "business_consequence":
            "Malicious state may propagate into later sessions.",
        "inherent_score": 37,
        "inherent_rating": "CRITICAL",
        "treatment": "MITIGATE",
        "required_controls": [
            "Session-bound memory",
            "Trust metadata",
            "Memory expiration",
        ],
        "control_owner": "AI Platform Team",
        "target_residual_score": 5,
        "target_residual_rating": "LOW",
        "risk_acceptance_allowed": True,
    },

    {
        "risk_id": "RISK-2807",
        "name": "Cross-Agent Memory Propagation",
        "domain": "MEMORY",
        "owner": "Agent Platform Owner",
        "affected_assets": [
            "Persistent Memory",
            "Agent Planner",
            "Multiple Agents",
        ],
        "business_consequence":
            "Compromise may spread across autonomous components.",
        "inherent_score": 38,
        "inherent_rating": "CRITICAL",
        "treatment": "MITIGATE",
        "required_controls": [
            "Agent-scoped memory",
            "Cross-agent isolation",
            "Memory provenance enforcement",
        ],
        "control_owner": "Agent Security Team",
        "target_residual_score": 5,
        "target_residual_rating": "LOW",
        "risk_acceptance_allowed": True,
    },

    {
        "risk_id": "RISK-2808",
        "name": "Agent Goal Hijacking",
        "domain": "AGENT",
        "owner": "Agent Platform Owner",
        "affected_assets": [
            "Agent Planner",
            "Trusted Task",
        ],
        "business_consequence":
            "Agent may pursue attacker-controlled goals.",
        "inherent_score": 33,
        "inherent_rating": "CRITICAL",
        "treatment": "MITIGATE",
        "required_controls": [
            "Trusted goal binding",
            "Task integrity checks",
            "Independent execution policy",
        ],
        "control_owner": "Agent Security Team",
        "target_residual_score": 7,
        "target_residual_rating": "MEDIUM",
        "risk_acceptance_allowed": True,
    },

    {
        "risk_id": "RISK-2809",
        "name": "Task Binding Bypass",
        "domain": "AGENT",
        "owner": "Agent Security Owner",
        "affected_assets": [
            "Trusted Task",
            "Agent Planner",
            "Tool Router",
        ],
        "business_consequence":
            "Model plans may exceed approved business intent.",
        "inherent_score": 33,
        "inherent_rating": "CRITICAL",
        "treatment": "MITIGATE",
        "required_controls": [
            "Cryptographic or logical task binding",
            "Tool-task correlation",
        ],
        "control_owner": "Agent Security Team",
        "target_residual_score": 6,
        "target_residual_rating": "MEDIUM",
        "risk_acceptance_allowed": True,
    },

    {
        "risk_id": "RISK-2810",
        "name": "Unsafe Privileged Tool Selection",
        "domain": "TOOL",
        "owner": "Tool Platform Owner",
        "affected_assets": [
            "Tool Router",
            "Delete Record Tool",
        ],
        "business_consequence":
            "Model-generated state may select destructive capability.",
        "inherent_score": 34,
        "inherent_rating": "CRITICAL",
        "treatment": "MITIGATE",
        "required_controls": [
            "Tool allowlisting",
            "Privilege-aware routing",
            "Independent authorization",
        ],
        "control_owner": "Tool Security Team",
        "target_residual_score": 5,
        "target_residual_rating": "LOW",
        "risk_acceptance_allowed": False,
    },

    {
        "risk_id": "RISK-2811",
        "name": "Target Substitution",
        "domain": "TOOL",
        "owner": "Tool Platform Owner",
        "affected_assets": [
            "Tool Router",
            "Restricted Record",
        ],
        "business_consequence":
            "Authorized actions may be redirected to restricted targets.",
        "inherent_score": 34,
        "inherent_rating": "CRITICAL",
        "treatment": "MITIGATE",
        "required_controls": [
            "Trusted target binding",
            "Resource-level authorization",
        ],
        "control_owner": "Tool Security Team",
        "target_residual_score": 5,
        "target_residual_rating": "LOW",
        "risk_acceptance_allowed": False,
    },

    {
        "risk_id": "RISK-2812",
        "name": "Tool Parameter Manipulation",
        "domain": "TOOL",
        "owner": "Tool Platform Owner",
        "affected_assets": [
            "Tool Parameters",
            "Privileged Tool Runtime",
        ],
        "business_consequence":
            "Valid functionality may execute with unsafe arguments.",
        "inherent_score": 34,
        "inherent_rating": "CRITICAL",
        "treatment": "MITIGATE",
        "required_controls": [
            "Strict schema validation",
            "Parameter allowlisting",
            "Execution-time validation",
        ],
        "control_owner": "Tool Security Team",
        "target_residual_score": 5,
        "target_residual_rating": "LOW",
        "risk_acceptance_allowed": False,
    },

    {
        "risk_id": "RISK-2813",
        "name": "Model-Generated Approval",
        "domain": "AUTHORIZATION",
        "owner": "Identity & Access Management",
        "affected_assets": [
            "Authorization Service",
            "Privileged Tools",
        ],
        "business_consequence":
            "Generated language may be mistaken for authorization evidence.",
        "inherent_score": 35,
        "inherent_rating": "CRITICAL",
        "treatment": "MITIGATE",
        "required_controls": [
            "External approval verification",
            "Non-model authorization state",
        ],
        "control_owner": "Identity Security Team",
        "target_residual_score": 4,
        "target_residual_rating": "LOW",
        "risk_acceptance_allowed": False,
    },

    {
        "risk_id": "RISK-2814",
        "name": "Fail-Open Authorization",
        "domain": "AUTHORIZATION",
        "owner": "Identity & Access Management",
        "affected_assets": [
            "Authorization Service",
            "Tool Runtime",
        ],
        "business_consequence":
            "Denied or missing authorization may still result in execution.",
        "inherent_score": 30,
        "inherent_rating": "CRITICAL",
        "treatment": "MITIGATE",
        "required_controls": [
            "Fail-closed authorization",
            "Execution deny enforcement",
        ],
        "control_owner": "Identity Security Team",
        "target_residual_score": 3,
        "target_residual_rating": "LOW",
        "risk_acceptance_allowed": False,
    },

    {
        "risk_id": "RISK-2815",
        "name": "Credential Exposure",
        "domain": "SECRET",
        "owner": "Platform Security",
        "affected_assets": [
            "API Credential",
            "Secret Store",
            "LLM Context",
        ],
        "business_consequence":
            "Credentials may enable downstream compromise.",
        "inherent_score": 32,
        "inherent_rating": "CRITICAL",
        "treatment": "MITIGATE",
        "required_controls": [
            "Secret isolation",
            "No model-visible credentials",
            "Credential redaction",
        ],
        "control_owner": "Platform Security",
        "target_residual_score": 5,
        "target_residual_rating": "LOW",
        "risk_acceptance_allowed": False,
    },

    {
        "risk_id": "RISK-2816",
        "name": "Credential Scope Abuse",
        "domain": "SECRET",
        "owner": "Platform Security",
        "affected_assets": [
            "API Credential",
            "Tool Runtime",
            "Downstream Services",
        ],
        "business_consequence":
            "Valid credentials may be used beyond intended scope.",
        "inherent_score": 37,
        "inherent_rating": "CRITICAL",
        "treatment": "MITIGATE",
        "required_controls": [
            "Least privilege",
            "Short-lived credentials",
            "Task-bound credentials",
        ],
        "control_owner": "Platform Security",
        "target_residual_score": 5,
        "target_residual_rating": "LOW",
        "risk_acceptance_allowed": False,
    },

    {
        "risk_id": "RISK-2817",
        "name": "Restricted Data Disclosure",
        "domain": "BUSINESS",
        "owner": "Business Data Owner",
        "affected_assets": [
            "Restricted Record",
            "Business Data",
        ],
        "business_consequence":
            "Sensitive business information may be exposed.",
        "inherent_score": 32,
        "inherent_rating": "CRITICAL",
        "treatment": "MITIGATE",
        "required_controls": [
            "Resource-level authorization",
            "DLP",
            "Data minimization",
        ],
        "control_owner": "Data Security Team",
        "target_residual_score": 5,
        "target_residual_rating": "LOW",
        "risk_acceptance_allowed": False,
    },

    {
        "risk_id": "RISK-2818",
        "name": "Restricted Data Modification",
        "domain": "BUSINESS",
        "owner": "Business Data Owner",
        "affected_assets": [
            "Restricted Record",
        ],
        "business_consequence":
            "Protected business data may be altered.",
        "inherent_score": 29,
        "inherent_rating": "CRITICAL",
        "treatment": "MITIGATE",
        "required_controls": [
            "Write authorization",
            "Transaction validation",
            "Audit logging",
        ],
        "control_owner": "Data Security Team",
        "target_residual_score": 4,
        "target_residual_rating": "LOW",
        "risk_acceptance_allowed": False,
    },

    {
        "risk_id": "RISK-2819",
        "name": "Restricted Data Destruction",
        "domain": "BUSINESS",
        "owner": "Business Data Owner",
        "affected_assets": [
            "Restricted Record",
        ],
        "business_consequence":
            "Critical business data may be destroyed.",
        "inherent_score": 29,
        "inherent_rating": "CRITICAL",
        "treatment": "MITIGATE",
        "required_controls": [
            "Independent destructive-action approval",
            "Soft-delete / recovery",
            "Resource authorization",
        ],
        "control_owner": "Data Security Team",
        "target_residual_score": 3,
        "target_residual_rating": "LOW",
        "risk_acceptance_allowed": False,
    },

    {
        "risk_id": "RISK-2820",
        "name": "Security Telemetry Suppression",
        "domain": "OBSERVABILITY",
        "owner": "AI SOC",
        "affected_assets": [
            "Security Telemetry",
            "Audit Trail",
        ],
        "business_consequence":
            "Detection, investigation, and accountability may fail.",
        "inherent_score": 26,
        "inherent_rating": "CRITICAL",
        "treatment": "MITIGATE",
        "required_controls": [
            "Tamper-evident logging",
            "Independent telemetry pipeline",
            "Alert on missing events",
        ],
        "control_owner": "AI SOC",
        "target_residual_score": 6,
        "target_residual_rating": "MEDIUM",
        "risk_acceptance_allowed": True,
    },

    {
        "risk_id": "RISK-2821",
        "name": "Resource Exhaustion",
        "domain": "AVAILABILITY",
        "owner": "AI Platform Owner",
        "affected_assets": [
            "LLM Runtime",
            "RAG",
            "Tool Runtime",
        ],
        "business_consequence":
            "Excessive AI activity may affect cost and availability.",
        "inherent_score": 19,
        "inherent_rating": "HIGH",
        "treatment": "MITIGATE",
        "required_controls": [
            "Rate limiting",
            "Execution budgets",
            "Concurrency controls",
        ],
        "control_owner": "AI Platform Team",
        "target_residual_score": 5,
        "target_residual_rating": "LOW",
        "risk_acceptance_allowed": True,
    },
]


# ============================================================
# ACCEPTANCE DECISION
# ============================================================

for risk in RISK_REGISTER:

    if risk["target_residual_rating"] == "CRITICAL":
        decision = "NOT_ACCEPTABLE"

    elif (
        risk["target_residual_rating"] == "HIGH"
        and not risk["risk_acceptance_allowed"]
    ):
        decision = "NOT_ACCEPTABLE"

    elif risk["risk_acceptance_allowed"]:
        decision = "ACCEPTABLE_AFTER_MITIGATION"

    else:
        decision = "REQUIRES_RISK_OWNER_APPROVAL"

    risk["target_acceptance_decision"] = decision


# ============================================================
# DEPLOYMENT GATE
# ============================================================

deployment_blockers = [
    risk
    for risk in RISK_REGISTER
    if risk["target_acceptance_decision"]
    == "NOT_ACCEPTABLE"
]


# ============================================================
# ANALYSIS
# ============================================================

domain_counter = Counter(
    risk["domain"]
    for risk in RISK_REGISTER
)

owner_counter = Counter(
    risk["owner"]
    for risk in RISK_REGISTER
)

target_rating_counter = Counter(
    risk["target_residual_rating"]
    for risk in RISK_REGISTER
)

treatment_counter = Counter(
    risk["treatment"]
    for risk in RISK_REGISTER
)

non_acceptance_allowed = [
    risk
    for risk in RISK_REGISTER
    if not risk["risk_acceptance_allowed"]
]

low_target_risks = [
    risk
    for risk in RISK_REGISTER
    if risk["target_residual_rating"]
    == "LOW"
]

medium_target_risks = [
    risk
    for risk in RISK_REGISTER
    if risk["target_residual_rating"]
    == "MEDIUM"
]


# ============================================================
# OUTPUT
# ============================================================

def header(title):

    print("\n" + "=" * 92)
    print(f"        {title}")
    print("=" * 92)


header("FORMAL AI SECURITY RISK REGISTER")

for risk in RISK_REGISTER:

    print(
        f"{risk['risk_id']} | "
        f"{risk['domain']} | "
        f"{risk['inherent_rating']} -> "
        f"{risk['target_residual_rating']} | "
        f"{risk['name']}"
    )

    print(
        f"  Risk Owner: "
        f"{risk['owner']}"
    )

    print(
        f"  Control Owner: "
        f"{risk['control_owner']}"
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
        f"  Inherent Score: "
        f"{risk['inherent_score']}"
    )

    print(
        f"  Treatment: "
        f"{risk['treatment']}"
    )

    print(
        "  Required Controls: "
        + ", ".join(
            risk["required_controls"]
        )
    )

    print(
        f"  Target Residual Score: "
        f"{risk['target_residual_score']}"
    )

    print(
        f"  Risk Acceptance Allowed: "
        f"{risk['risk_acceptance_allowed']}"
    )

    print(
        f"  Target Acceptance Decision: "
        f"{risk['target_acceptance_decision']}"
    )


header("RISK DOMAIN DISTRIBUTION")

for domain, count in sorted(
    domain_counter.items()
):

    print(
        f"{domain}: {count}"
    )


header("RISK OWNER DISTRIBUTION")

for owner, count in sorted(
    owner_counter.items()
):

    print(
        f"{owner}: {count}"
    )


header("TARGET RESIDUAL-RISK DISTRIBUTION")

for rating in [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
]:

    print(
        f"{rating}: "
        f"{target_rating_counter.get(rating, 0)}"
    )


header("NON-ACCEPTABLE-BY-DEFAULT RISKS")

for risk in non_acceptance_allowed:

    print(
        f"{risk['risk_id']} | "
        f"{risk['domain']} | "
        f"{risk['name']}"
    )


header("TARGET LOW-RISK ITEMS")

for risk in low_target_risks:

    print(
        f"{risk['risk_id']} | "
        f"Target={risk['target_residual_score']} | "
        f"{risk['name']}"
    )


header("TARGET MEDIUM-RISK ITEMS")

for risk in medium_target_risks:

    print(
        f"{risk['risk_id']} | "
        f"Target={risk['target_residual_score']} | "
        f"{risk['name']}"
    )


# ============================================================
# DEPLOYMENT DECISION
# ============================================================

header("PRE-DEPLOYMENT RISK DECISION")

current_critical_count = sum(
    1
    for risk in RISK_REGISTER
    if risk["inherent_rating"]
    == "CRITICAL"
)

target_critical_count = sum(
    1
    for risk in RISK_REGISTER
    if risk["target_residual_rating"]
    == "CRITICAL"
)

deployment_ready = (
    target_critical_count == 0
    and len(deployment_blockers) == 0
)


print(
    f"Current Critical Risks: "
    f"{current_critical_count}"
)

print(
    f"Target Critical Residual Risks: "
    f"{target_critical_count}"
)

print(
    f"Explicit Deployment Blockers: "
    f"{len(deployment_blockers)}"
)

print(
    f"Target Architecture Deployment Ready: "
    f"{deployment_ready}"
)


# ============================================================
# SUMMARY
# ============================================================

header("FORMAL RISK REGISTER SUMMARY")

print(
    f"Risk Records: "
    f"{len(RISK_REGISTER)}"
)

print(
    f"Risk Domains: "
    f"{len(domain_counter)}"
)

print(
    f"Risk Owners: "
    f"{len(owner_counter)}"
)

print(
    f"Treatment Types: "
    f"{len(treatment_counter)}"
)

print(
    f"Risks Not Acceptable By Default: "
    f"{len(non_acceptance_allowed)}"
)

print(
    f"Target Low Risks: "
    f"{len(low_target_risks)}"
)

print(
    f"Target Medium Risks: "
    f"{len(medium_target_risks)}"
)

print(
    f"Deployment Blockers At Target State: "
    f"{len(deployment_blockers)}"
)


# ============================================================
# VALIDATION
# ============================================================

header("FORMAL RISK-REGISTER SECURITY CHECKS")

risk_ids = [
    risk["risk_id"]
    for risk in RISK_REGISTER
]

checks = {
    "Unique Risk IDs":
        len(risk_ids)
        == len(set(risk_ids)),

    "All Risks Have Owners":
        all(
            risk["owner"]
            for risk in RISK_REGISTER
        ),

    "All Risks Have Control Owners":
        all(
            risk["control_owner"]
            for risk in RISK_REGISTER
        ),

    "All Risks Have Affected Assets":
        all(
            risk["affected_assets"]
            for risk in RISK_REGISTER
        ),

    "All Risks Have Business Consequences":
        all(
            risk["business_consequence"]
            for risk in RISK_REGISTER
        ),

    "All Risks Have Treatments":
        all(
            risk["treatment"]
            for risk in RISK_REGISTER
        ),

    "All Risks Have Required Controls":
        all(
            risk["required_controls"]
            for risk in RISK_REGISTER
        ),

    "All Risks Have Target Residual State":
        all(
            risk["target_residual_score"] >= 1
            and
            risk["target_residual_rating"]
            in {
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL",
            }
            for risk in RISK_REGISTER
        ),

    "Acceptance Decisions Generated":
        all(
            risk[
                "target_acceptance_decision"
            ]
            for risk in RISK_REGISTER
        ),

    "High-Risk Non-Acceptance Policy Present":
        len(
            non_acceptance_allowed
        ) > 0,

    "No Target Critical Residual Risks":
        target_critical_count == 0,
}


for check, result in checks.items():

    print(
        f"{check}: {result}"
    )


risk_register_valid = all(
    checks.values()
)


print(
    f"\nFormal AI Security Risk Register Valid: "
    f"{risk_register_valid}"
)


# ============================================================
# EXPORT
# ============================================================

REPORT = {
    "lab":
        "Day 28 Lab 13",

    "title":
        "Formal AI Security Risk Register",

    "risk_register":
        RISK_REGISTER,

    "metrics": {
        "risk_records":
            len(RISK_REGISTER),

        "risk_domains":
            len(domain_counter),

        "risk_owners":
            len(owner_counter),

        "non_acceptance_allowed":
            len(
                non_acceptance_allowed
            ),

        "target_low_risks":
            len(
                low_target_risks
            ),

        "target_medium_risks":
            len(
                medium_target_risks
            ),

        "target_critical_risks":
            target_critical_count,

        "deployment_blockers":
            len(
                deployment_blockers
            ),

        "target_architecture_deployment_ready":
            deployment_ready,
    },

    "security_checks":
        checks,

    "risk_register_valid":
        risk_register_valid,
}


OUTPUT_FILE = (
    "day28-formal-ai-security-risk-register-evidence.json"
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


# ============================================================
# INTERPRETATION
# ============================================================

print("\nSecurity Interpretation:")

print(
    "The formal AI security risk register converts technical threat-model "
    "findings into accountable business risk records with named risk owners, "
    "control owners, affected assets, business consequences, treatments, "
    "target residual states and acceptance decisions."
)

print(
    "Privileged execution, authorization, secrets and destructive business "
    "operations are deliberately treated as non-acceptable by default and "
    "must reach a low target residual-risk state before deployment."
)

print(
    "The risk register therefore creates the governance bridge between "
    "technical AI threat modeling and security architecture, engineering "
    "prioritization and deployment approval."
)

print("\nCore Principle:")

print(
    "AI security should be designed from identified threats and trust "
    "boundaries, not added only after vulnerabilities are discovered."
)