"""
Day 28 Lab 8
Agent & Tool-Execution Threat Modeling

Purpose:
Model threats involving autonomous agent planning, tool selection,
parameter manipulation, target substitution, authorization,
credentials, privileged execution, destructive actions and
agent-to-business-impact attack paths.

Core Principle:
AI security should be designed from identified threats and trust
boundaries, not added only after vulnerabilities are discovered.
"""

import json
from collections import Counter


print(
    "\n=== Day 28 Lab 8: "
    "Agent & Tool-Execution Threat Modeling ===\n"
)


# ============================================================
# AGENT / TOOL COMPONENT MODEL
# ============================================================

COMPONENTS = [
    {
        "component_id": "AGT-COMP-01",
        "name": "LLM Runtime",
        "trust": "mixed_runtime",
    },

    {
        "component_id": "AGT-COMP-02",
        "name": "Agent Planner",
        "trust": "trusted_runtime",
    },

    {
        "component_id": "AGT-COMP-03",
        "name": "Task Binding Service",
        "trust": "security_controlled",
    },

    {
        "component_id": "AGT-COMP-04",
        "name": "Tool Router",
        "trust": "trusted_runtime",
    },

    {
        "component_id": "AGT-COMP-05",
        "name": "Parameter Validator",
        "trust": "security_controlled",
    },

    {
        "component_id": "AGT-COMP-06",
        "name": "Authorization Service",
        "trust": "security_controlled",
    },

    {
        "component_id": "AGT-COMP-07",
        "name": "Secret Store",
        "trust": "restricted",
    },

    {
        "component_id": "AGT-COMP-08",
        "name": "Read Record Tool",
        "trust": "privileged_execution",
    },

    {
        "component_id": "AGT-COMP-09",
        "name": "Delete Record Tool",
        "trust": "privileged_execution",
    },

    {
        "component_id": "AGT-COMP-10",
        "name": "Restricted Business Record",
        "trust": "restricted",
    },

    {
        "component_id": "AGT-COMP-11",
        "name": "Downstream Record Service",
        "trust": "privileged_execution",
    },

    {
        "component_id": "AGT-COMP-12",
        "name": "Security Telemetry",
        "trust": "security_monitoring",
    },
]


# ============================================================
# AGENT / TOOL THREAT REGISTER
# ============================================================

THREATS = [
    {
        "threat_id": "AGT-THR-2801",
        "name": "Agent Goal Hijacking",
        "category": "GOAL_MANIPULATION",
        "component": "AGT-COMP-02",
        "scenario":
            "Untrusted prompt, RAG, or memory state modifies the intended agent objective.",
        "impact":
            "The agent may pursue attacker-controlled goals instead of the trusted task.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2802",
        "name": "Agent Task Drift",
        "category": "GOAL_MANIPULATION",
        "component": "AGT-COMP-02",
        "scenario":
            "The agent gradually expands its actions beyond the original authorized task.",
        "impact":
            "Execution scope may exceed business intent.",
        "likelihood": 4,
        "impact_score": 4,
    },

    {
        "threat_id": "AGT-THR-2803",
        "name": "Model-Generated Privilege Escalation Proposal",
        "category": "PRIVILEGE_ESCALATION",
        "component": "AGT-COMP-02",
        "scenario":
            "The agent proposes a higher-privilege action than the trusted task requires.",
        "impact":
            "Model-generated reasoning may approach privileged execution.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2804",
        "name": "Agent Delegation Abuse",
        "category": "DELEGATION",
        "component": "AGT-COMP-02",
        "scenario":
            "The agent delegates work to another agent or component with broader permissions.",
        "impact":
            "Privilege may expand indirectly through delegation.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2805",
        "name": "Task Binding Bypass",
        "category": "TASK_BINDING",
        "component": "AGT-COMP-03",
        "scenario":
            "Proposed tool, target, or action is not cryptographically or logically bound to the trusted task.",
        "impact":
            "A legitimate request may be transformed into an unrelated privileged action.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2806",
        "name": "Trusted Target Substitution",
        "category": "TARGET_MANIPULATION",
        "component": "AGT-COMP-03",
        "scenario":
            "The authorized target is replaced with a restricted or attacker-selected resource.",
        "impact":
            "Safe functionality may be redirected toward high-value assets.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2807",
        "name": "Unsafe Tool Selection",
        "category": "TOOL_SELECTION",
        "component": "AGT-COMP-04",
        "scenario":
            "Tool router selects a privileged tool based only on model-generated state.",
        "impact":
            "The model may gain indirect execution authority.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2808",
        "name": "Tool Confusion",
        "category": "TOOL_SELECTION",
        "component": "AGT-COMP-04",
        "scenario":
            "A tool with similar naming or semantics is substituted for the intended tool.",
        "impact":
            "Unexpected functionality may execute.",
        "likelihood": 3,
        "impact_score": 4,
    },

    {
        "threat_id": "AGT-THR-2809",
        "name": "Tool Parameter Injection",
        "category": "PARAMETER_MANIPULATION",
        "component": "AGT-COMP-05",
        "scenario":
            "Attacker-controlled data modifies tool parameters.",
        "impact":
            "A valid tool call may operate with unsafe arguments.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2810",
        "name": "Parameter Scope Expansion",
        "category": "PARAMETER_MANIPULATION",
        "component": "AGT-COMP-05",
        "scenario":
            "Tool parameters expand from one authorized object to broader records or resources.",
        "impact":
            "Execution may exceed intended scope.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2811",
        "name": "Parameter Validation Bypass",
        "category": "PARAMETER_MANIPULATION",
        "component": "AGT-COMP-05",
        "scenario":
            "Malformed, nested, encoded, or alternative parameter representations bypass validation.",
        "impact":
            "Security policy may be bypassed at execution time.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2812",
        "name": "Model-Generated Approval",
        "category": "AUTHORITY_CONFUSION",
        "component": "AGT-COMP-06",
        "scenario":
            "The model generates text claiming that an action has already been approved.",
        "impact":
            "Natural-language output may be mistaken for authorization evidence.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2813",
        "name": "Approval Token Spoofing",
        "category": "AUTHORITY_CONFUSION",
        "component": "AGT-COMP-06",
        "scenario":
            "Attacker supplies or fabricates an approval token, identifier, or state.",
        "impact":
            "Unauthorized requests may appear valid.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2814",
        "name": "Authorization Decision Tampering",
        "category": "AUTHORIZATION",
        "component": "AGT-COMP-06",
        "scenario":
            "An authorization denial is changed, ignored, or replaced with approval.",
        "impact":
            "Privileged execution may proceed without valid authorization.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2815",
        "name": "Fail-Open Authorization",
        "category": "AUTHORIZATION",
        "component": "AGT-COMP-06",
        "scenario":
            "Execution proceeds when authorization is unavailable, malformed, missing, or denied.",
        "impact":
            "Sensitive operations may execute without approval.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2816",
        "name": "Identity Confusion",
        "category": "IDENTITY",
        "component": "AGT-COMP-06",
        "scenario":
            "Agent identity, user identity, service identity, and tool identity are incorrectly conflated.",
        "impact":
            "Actions may inherit permissions belonging to another principal.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2817",
        "name": "Credential Exposure to Model Context",
        "category": "SECRET_SECURITY",
        "component": "AGT-COMP-07",
        "scenario":
            "API keys or tokens are unnecessarily inserted into model-visible context.",
        "impact":
            "Secrets may be disclosed through prompts, outputs, memory, or logs.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2818",
        "name": "Credential Scope Abuse",
        "category": "SECRET_SECURITY",
        "component": "AGT-COMP-07",
        "scenario":
            "A valid credential is used outside its intended tool, target, or task.",
        "impact":
            "Compromise may gain broader downstream capability.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2819",
        "name": "Credential Replay",
        "category": "SECRET_SECURITY",
        "component": "AGT-COMP-07",
        "scenario":
            "Captured credential state is reused for later unauthorized actions.",
        "impact":
            "Attackers may retain access after the originating workflow ends.",
        "likelihood": 3,
        "impact_score": 4,
    },

    {
        "threat_id": "AGT-THR-2820",
        "name": "Unauthorized Read Tool Use",
        "category": "TOOL_EXECUTION",
        "component": "AGT-COMP-08",
        "scenario":
            "The read tool is used against data outside the authorized task scope.",
        "impact":
            "Sensitive business data may be exposed.",
        "likelihood": 4,
        "impact_score": 4,
    },

    {
        "threat_id": "AGT-THR-2821",
        "name": "Unauthorized Delete Tool Use",
        "category": "PRIVILEGED_EXECUTION",
        "component": "AGT-COMP-09",
        "scenario":
            "Delete capability executes without valid authorization.",
        "impact":
            "Business data may be destroyed.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2822",
        "name": "Restricted Target Deletion",
        "category": "PRIVILEGED_EXECUTION",
        "component": "AGT-COMP-09",
        "scenario":
            "Delete tool operates on a restricted record instead of the authorized target.",
        "impact":
            "Critical business integrity and availability may be affected.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2823",
        "name": "Repeated Destructive Action",
        "category": "PRIVILEGED_EXECUTION",
        "component": "AGT-COMP-09",
        "scenario":
            "Agent loops or retries destructive operations without explicit reauthorization.",
        "impact":
            "Damage may multiply across repeated executions.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2824",
        "name": "Restricted Business Record Disclosure",
        "category": "BUSINESS_IMPACT",
        "component": "AGT-COMP-10",
        "scenario":
            "Tool or agent reads restricted business data without valid scope.",
        "impact":
            "Confidentiality may be compromised.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2825",
        "name": "Restricted Business Record Modification",
        "category": "BUSINESS_IMPACT",
        "component": "AGT-COMP-10",
        "scenario":
            "Agent or tool modifies protected business data.",
        "impact":
            "Business integrity may be affected.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2826",
        "name": "Restricted Business Record Destruction",
        "category": "BUSINESS_IMPACT",
        "component": "AGT-COMP-10",
        "scenario":
            "Privileged tool destroys restricted business data.",
        "impact":
            "Critical availability and integrity impact may occur.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2827",
        "name": "Downstream Service Trust Abuse",
        "category": "DOWNSTREAM_TRUST",
        "component": "AGT-COMP-11",
        "scenario":
            "Downstream service trusts upstream AI workflow assertions without independent validation.",
        "impact":
            "Unsafe model-generated state may propagate into business systems.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2828",
        "name": "Tool Call Replay",
        "category": "DOWNSTREAM_TRUST",
        "component": "AGT-COMP-11",
        "scenario":
            "A previously authorized tool request is replayed after its authorization context expires.",
        "impact":
            "Sensitive actions may execute outside the approved transaction window.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "AGT-THR-2829",
        "name": "Agent Execution Loop",
        "category": "AVAILABILITY",
        "component": "AGT-COMP-02",
        "scenario":
            "Agent repeatedly plans and executes actions without bounded termination.",
        "impact":
            "Cost, capacity, downstream rate limits, or availability may be affected.",
        "likelihood": 4,
        "impact_score": 3,
    },

    {
        "threat_id": "AGT-THR-2830",
        "name": "Tool Invocation Flood",
        "category": "AVAILABILITY",
        "component": "AGT-COMP-04",
        "scenario":
            "Agent generates excessive tool calls or retries.",
        "impact":
            "Tool services may be exhausted or rate-limited.",
        "likelihood": 4,
        "impact_score": 3,
    },

    {
        "threat_id": "AGT-THR-2831",
        "name": "Tool Execution Telemetry Suppression",
        "category": "OBSERVABILITY",
        "component": "AGT-COMP-12",
        "scenario":
            "Tool, target, parameter, authorization, or execution events are not logged.",
        "impact":
            "Unsafe agent behavior may become difficult to detect or reconstruct.",
        "likelihood": 3,
        "impact_score": 4,
    },

    {
        "threat_id": "AGT-THR-2832",
        "name": "Authorization Evidence Tampering",
        "category": "OBSERVABILITY",
        "component": "AGT-COMP-12",
        "scenario":
            "Authorization or tool-execution evidence is altered or removed.",
        "impact":
            "Forensic reconstruction and accountability may fail.",
        "likelihood": 3,
        "impact_score": 5,
    },
]


# ============================================================
# RISK SCORING
# ============================================================

def classify(score):

    if score >= 20:
        return "CRITICAL"

    if score >= 15:
        return "HIGH"

    if score >= 8:
        return "MEDIUM"

    return "LOW"


for threat in THREATS:

    threat["risk_score"] = (
        threat["likelihood"]
        * threat["impact_score"]
    )

    threat["priority"] = classify(
        threat["risk_score"]
    )


# ============================================================
# SECURITY CONTROLS
# ============================================================

CONTROLS = [
    {
        "control_id": "AGT-CTRL-01",
        "name": "Trusted Goal / Task Binding",
        "addresses": [
            "AGT-THR-2801",
            "AGT-THR-2802",
            "AGT-THR-2805",
        ],
    },

    {
        "control_id": "AGT-CTRL-02",
        "name": "Agent Delegation Policy",
        "addresses": [
            "AGT-THR-2804",
        ],
    },

    {
        "control_id": "AGT-CTRL-03",
        "name": "Independent Privilege Approval",
        "addresses": [
            "AGT-THR-2803",
            "AGT-THR-2807",
            "AGT-THR-2821",
            "AGT-THR-2822",
            "AGT-THR-2823",
        ],
    },

    {
        "control_id": "AGT-CTRL-04",
        "name": "Tool Allowlisting & Capability Policy",
        "addresses": [
            "AGT-THR-2807",
            "AGT-THR-2808",
        ],
    },

    {
        "control_id": "AGT-CTRL-05",
        "name": "Strict Parameter Schema Validation",
        "addresses": [
            "AGT-THR-2809",
            "AGT-THR-2810",
            "AGT-THR-2811",
        ],
    },

    {
        "control_id": "AGT-CTRL-06",
        "name": "Trusted Target Binding",
        "addresses": [
            "AGT-THR-2806",
            "AGT-THR-2822",
        ],
    },

    {
        "control_id": "AGT-CTRL-07",
        "name": "Fail-Closed Independent Authorization",
        "addresses": [
            "AGT-THR-2812",
            "AGT-THR-2813",
            "AGT-THR-2814",
            "AGT-THR-2815",
            "AGT-THR-2816",
        ],
    },

    {
        "control_id": "AGT-CTRL-08",
        "name": "Secret Isolation & Short-Lived Credentials",
        "addresses": [
            "AGT-THR-2817",
            "AGT-THR-2818",
            "AGT-THR-2819",
        ],
    },

    {
        "control_id": "AGT-CTRL-09",
        "name": "Resource-Level Authorization",
        "addresses": [
            "AGT-THR-2820",
            "AGT-THR-2824",
            "AGT-THR-2825",
            "AGT-THR-2826",
        ],
    },

    {
        "control_id": "AGT-CTRL-10",
        "name": "Downstream Independent Validation",
        "addresses": [
            "AGT-THR-2827",
            "AGT-THR-2828",
        ],
    },

    {
        "control_id": "AGT-CTRL-11",
        "name": "Agent / Tool Execution Budgets",
        "addresses": [
            "AGT-THR-2829",
            "AGT-THR-2830",
        ],
    },

    {
        "control_id": "AGT-CTRL-12",
        "name": "Tamper-Evident Execution Telemetry",
        "addresses": [
            "AGT-THR-2831",
            "AGT-THR-2832",
        ],
    },
]


covered_threats = {
    threat_id
    for control in CONTROLS
    for threat_id in control["addresses"]
}


# ============================================================
# MULTI-STAGE ABUSE CHAINS
# ============================================================

ABUSE_CHAINS = [
    {
        "chain_id": "AGT-CHAIN-01",
        "name": "Goal Hijacking to Privileged Execution",
        "steps": [
            "AGT-THR-2801",
            "AGT-THR-2803",
            "AGT-THR-2807",
            "AGT-THR-2821",
        ],
        "impact":
            "Compromised agent reasoning reaches privileged execution.",
    },

    {
        "chain_id": "AGT-CHAIN-02",
        "name": "Target Substitution to Restricted Record Destruction",
        "steps": [
            "AGT-THR-2806",
            "AGT-THR-2809",
            "AGT-THR-2822",
            "AGT-THR-2826",
        ],
        "impact":
            "Legitimate tool flow is redirected toward destructive business impact.",
    },

    {
        "chain_id": "AGT-CHAIN-03",
        "name": "Fake Approval to Authorization Bypass",
        "steps": [
            "AGT-THR-2812",
            "AGT-THR-2813",
            "AGT-THR-2815",
            "AGT-THR-2821",
        ],
        "impact":
            "Fabricated approval state results in unauthorized privileged execution.",
    },

    {
        "chain_id": "AGT-CHAIN-04",
        "name": "Credential Abuse to Downstream Impact",
        "steps": [
            "AGT-THR-2817",
            "AGT-THR-2818",
            "AGT-THR-2827",
            "AGT-THR-2824",
        ],
        "impact":
            "Exposed or over-privileged credentials enable unauthorized downstream access.",
    },

    {
        "chain_id": "AGT-CHAIN-05",
        "name": "Fail-Open Authorization to Destructive Action",
        "steps": [
            "AGT-THR-2814",
            "AGT-THR-2815",
            "AGT-THR-2821",
            "AGT-THR-2826",
        ],
        "impact":
            "Authorization failure becomes direct business impact.",
    },
]


# ============================================================
# ANALYSIS
# ============================================================

category_counter = Counter(
    threat["category"]
    for threat in THREATS
)

priority_counter = Counter(
    threat["priority"]
    for threat in THREATS
)

high_critical = [
    threat
    for threat in THREATS
    if threat["priority"]
    in {"CRITICAL", "HIGH"}
]

privilege_threats = [
    threat
    for threat in THREATS
    if threat["category"]
    in {
        "PRIVILEGE_ESCALATION",
        "PRIVILEGED_EXECUTION",
        "AUTHORIZATION",
        "AUTHORITY_CONFUSION",
    }
]

tool_manipulation_threats = [
    threat
    for threat in THREATS
    if threat["category"]
    in {
        "TOOL_SELECTION",
        "PARAMETER_MANIPULATION",
        "TARGET_MANIPULATION",
    }
]

business_impact_threats = [
    threat
    for threat in THREATS
    if threat["category"]
    in {
        "BUSINESS_IMPACT",
        "PRIVILEGED_EXECUTION",
        "DOWNSTREAM_TRUST",
    }
]

secret_identity_threats = [
    threat
    for threat in THREATS
    if threat["category"]
    in {
        "SECRET_SECURITY",
        "IDENTITY",
    }
]


# ============================================================
# OUTPUT
# ============================================================

def header(title):

    print("\n" + "=" * 84)
    print(f"        {title}")
    print("=" * 84)


header("AGENT / TOOL COMPONENT MODEL")

for component in COMPONENTS:

    print(
        f"{component['component_id']} | "
        f"{component['trust']} | "
        f"{component['name']}"
    )


header("AGENT / TOOL THREAT REGISTER")

for threat in THREATS:

    print(
        f"{threat['threat_id']} | "
        f"{threat['category']} | "
        f"{threat['priority']} | "
        f"Risk={threat['risk_score']} | "
        f"{threat['name']}"
    )

    print(
        f"  Component: {threat['component']}"
    )

    print(
        f"  Scenario: {threat['scenario']}"
    )

    print(
        f"  Impact: {threat['impact']}"
    )


header("AGENT / TOOL THREAT CATEGORY DISTRIBUTION")

for category, count in sorted(
    category_counter.items()
):

    print(
        f"{category}: {count}"
    )


header("AGENT / TOOL THREAT PRIORITY DISTRIBUTION")

for priority in [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
]:

    print(
        f"{priority}: "
        f"{priority_counter.get(priority, 0)}"
    )


header("HIGH / CRITICAL AGENT / TOOL THREATS")

for threat in sorted(
    high_critical,
    key=lambda item: item["risk_score"],
    reverse=True,
):

    print(
        f"{threat['threat_id']} | "
        f"{threat['priority']} | "
        f"Risk={threat['risk_score']} | "
        f"{threat['name']}"
    )


header("PRIVILEGE / AUTHORIZATION THREATS")

for threat in privilege_threats:

    print(
        f"{threat['threat_id']} | "
        f"{threat['category']} | "
        f"{threat['name']}"
    )


header("TOOL / TARGET / PARAMETER THREATS")

for threat in tool_manipulation_threats:

    print(
        f"{threat['threat_id']} | "
        f"{threat['category']} | "
        f"{threat['name']}"
    )


header("SECRET / IDENTITY THREATS")

for threat in secret_identity_threats:

    print(
        f"{threat['threat_id']} | "
        f"{threat['category']} | "
        f"{threat['name']}"
    )


header("BUSINESS-IMPACT THREATS")

for threat in business_impact_threats:

    print(
        f"{threat['threat_id']} | "
        f"{threat['category']} | "
        f"{threat['name']}"
    )


header("AGENT / TOOL SECURITY CONTROL MAPPING")

for control in CONTROLS:

    print(
        f"{control['control_id']} | "
        f"{control['name']}"
    )

    print(
        "  Threats: "
        + ", ".join(
            control["addresses"]
        )
    )


header("AGENT / TOOL ABUSE CHAINS")

for chain in ABUSE_CHAINS:

    print(
        f"{chain['chain_id']} | "
        f"{chain['name']}"
    )

    print(
        "  Path: "
        + " -> ".join(
            chain["steps"]
        )
    )

    print(
        f"  Impact: "
        f"{chain['impact']}"
    )


# ============================================================
# SUMMARY
# ============================================================

header("AGENT / TOOL THREAT-MODEL SUMMARY")

print(
    f"Agent / Tool Components: "
    f"{len(COMPONENTS)}"
)

print(
    f"Agent / Tool Threat Scenarios: "
    f"{len(THREATS)}"
)

print(
    f"Threat Categories: "
    f"{len(category_counter)}"
)

print(
    f"High/Critical Threats: "
    f"{len(high_critical)}"
)

print(
    f"Privilege / Authorization Threats: "
    f"{len(privilege_threats)}"
)

print(
    f"Tool / Target / Parameter Threats: "
    f"{len(tool_manipulation_threats)}"
)

print(
    f"Secret / Identity Threats: "
    f"{len(secret_identity_threats)}"
)

print(
    f"Business-Impact Threats: "
    f"{len(business_impact_threats)}"
)

print(
    f"Security Controls: "
    f"{len(CONTROLS)}"
)

print(
    f"Threats With Control Coverage: "
    f"{len(covered_threats)} / "
    f"{len(THREATS)}"
)

print(
    f"Multi-Stage Agent / Tool Abuse Chains: "
    f"{len(ABUSE_CHAINS)}"
)


# ============================================================
# VALIDATION
# ============================================================

header("AGENT / TOOL THREAT-MODEL SECURITY CHECKS")

threat_ids = [
    threat["threat_id"]
    for threat in THREATS
]

component_ids = {
    component["component_id"]
    for component in COMPONENTS
}

checks = {
    "Unique Threat IDs":
        len(threat_ids)
        == len(set(threat_ids)),

    "All Threat Components Valid":
        all(
            threat["component"]
            in component_ids
            for threat in THREATS
        ),

    "Goal Hijacking Identified":
        any(
            threat["name"]
            == "Agent Goal Hijacking"
            for threat in THREATS
        ),

    "Privilege Escalation Identified":
        any(
            threat["category"]
            == "PRIVILEGE_ESCALATION"
            for threat in THREATS
        ),

    "Tool Selection Threats Identified":
        any(
            threat["category"]
            == "TOOL_SELECTION"
            for threat in THREATS
        ),

    "Parameter Manipulation Identified":
        any(
            threat["category"]
            == "PARAMETER_MANIPULATION"
            for threat in THREATS
        ),

    "Target Manipulation Identified":
        any(
            threat["category"]
            == "TARGET_MANIPULATION"
            for threat in THREATS
        ),

    "Authorization Threats Identified":
        any(
            threat["category"]
            == "AUTHORIZATION"
            for threat in THREATS
        ),

    "Authority Confusion Identified":
        any(
            threat["category"]
            == "AUTHORITY_CONFUSION"
            for threat in THREATS
        ),

    "Secret Security Threats Identified":
        any(
            threat["category"]
            == "SECRET_SECURITY"
            for threat in THREATS
        ),

    "Identity Threat Identified":
        any(
            threat["category"]
            == "IDENTITY"
            for threat in THREATS
        ),

    "Privileged Execution Threats Identified":
        any(
            threat["category"]
            == "PRIVILEGED_EXECUTION"
            for threat in THREATS
        ),

    "Business Impact Threats Identified":
        any(
            threat["category"]
            == "BUSINESS_IMPACT"
            for threat in THREATS
        ),

    "Downstream Trust Threats Identified":
        any(
            threat["category"]
            == "DOWNSTREAM_TRUST"
            for threat in THREATS
        ),

    "Availability Threats Identified":
        any(
            threat["category"]
            == "AVAILABILITY"
            for threat in THREATS
        ),

    "Observability Threats Identified":
        any(
            threat["category"]
            == "OBSERVABILITY"
            for threat in THREATS
        ),

    "All Threats Have Control Coverage":
        all(
            threat["threat_id"]
            in covered_threats
            for threat in THREATS
        ),

    "Multi-Stage Abuse Chains Identified":
        len(ABUSE_CHAINS) > 0,
}


for check, result in checks.items():

    print(
        f"{check}: {result}"
    )


agent_tool_model_valid = all(
    checks.values()
)


print(
    f"\nAgent / Tool-Execution Threat Model Valid: "
    f"{agent_tool_model_valid}"
)


# ============================================================
# EXPORT
# ============================================================

REPORT = {
    "lab":
        "Day 28 Lab 8",

    "title":
        "Agent & Tool-Execution Threat Modeling",

    "components":
        COMPONENTS,

    "threats":
        THREATS,

    "controls":
        CONTROLS,

    "abuse_chains":
        ABUSE_CHAINS,

    "metrics": {
        "components":
            len(COMPONENTS),

        "threat_scenarios":
            len(THREATS),

        "threat_categories":
            len(category_counter),

        "high_critical_threats":
            len(high_critical),

        "privilege_authorization_threats":
            len(privilege_threats),

        "tool_target_parameter_threats":
            len(tool_manipulation_threats),

        "secret_identity_threats":
            len(secret_identity_threats),

        "business_impact_threats":
            len(business_impact_threats),

        "security_controls":
            len(CONTROLS),

        "threats_with_control_coverage":
            len(covered_threats),

        "abuse_chains":
            len(ABUSE_CHAINS),
    },

    "security_checks":
        checks,

    "agent_tool_model_valid":
        agent_tool_model_valid,
}


OUTPUT_FILE = (
    "day28-agent-tool-execution-threat-model-evidence.json"
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
    "Agentic AI becomes materially higher risk when model-generated "
    "reasoning can cross into tools, credentials, authorization, "
    "privileged operations, or downstream business systems."
)

print(
    "Tool selection, parameters, targets, approval state and credentials "
    "must therefore remain independently constrained by trusted task state "
    "and external authorization rather than by model-generated language."
)

print(
    "Secure agent architecture should enforce task binding, least privilege, "
    "strict parameter validation, fail-closed authorization, short-lived "
    "credentials, downstream validation, bounded execution, and complete "
    "security telemetry."
)

print("\nCore Principle:")

print(
    "AI security should be designed from identified threats and trust "
    "boundaries, not added only after vulnerabilities are discovered."
)