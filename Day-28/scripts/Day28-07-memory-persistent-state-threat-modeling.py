"""
Day 28 Lab 7
Memory & Persistent-State Threat Modeling

Purpose:
Model threats involving persistent AI memory, memory writes,
cross-session state, cross-agent propagation, stale trust,
sensitive-data persistence, poisoned state, integrity failures,
and memory-to-tool abuse paths.

Core Principle:
AI security should be designed from identified threats and trust
boundaries, not added only after vulnerabilities are discovered.
"""

import json
from collections import Counter


print(
    "\n=== Day 28 Lab 7: "
    "Memory & Persistent-State Threat Modeling ===\n"
)


# ============================================================
# MEMORY COMPONENT MODEL
# ============================================================

MEMORY_COMPONENTS = [
    {
        "component_id": "MEM-COMP-01",
        "name": "Memory Write Interface",
        "trust": "mixed",
    },

    {
        "component_id": "MEM-COMP-02",
        "name": "Memory Authorization Gateway",
        "trust": "security_controlled",
    },

    {
        "component_id": "MEM-COMP-03",
        "name": "Persistent Memory Store",
        "trust": "sensitive",
    },

    {
        "component_id": "MEM-COMP-04",
        "name": "Memory Metadata Store",
        "trust": "sensitive",
    },

    {
        "component_id": "MEM-COMP-05",
        "name": "Memory Retrieval Service",
        "trust": "internal",
    },

    {
        "component_id": "MEM-COMP-06",
        "name": "Session Context",
        "trust": "mixed",
    },

    {
        "component_id": "MEM-COMP-07",
        "name": "Agent Planner",
        "trust": "trusted_runtime",
    },

    {
        "component_id": "MEM-COMP-08",
        "name": "Tool Router",
        "trust": "trusted_runtime",
    },

    {
        "component_id": "MEM-COMP-09",
        "name": "Authorization Service",
        "trust": "security_controlled",
    },

    {
        "component_id": "MEM-COMP-10",
        "name": "Security Telemetry",
        "trust": "security_monitoring",
    },
]


# ============================================================
# MEMORY THREAT REGISTER
# ============================================================

THREATS = [
    {
        "threat_id": "MEM-THR-2801",
        "name": "Unauthorized Memory Write",
        "category": "WRITE_AUTHORIZATION",
        "component": "MEM-COMP-01",
        "scenario":
            "Model or user-controlled state is written into persistent memory without explicit authorization.",
        "impact":
            "Untrusted content gains durable influence over future behavior.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "MEM-THR-2802",
        "name": "Persistent Instruction Poisoning",
        "category": "MEMORY_POISONING",
        "component": "MEM-COMP-01",
        "scenario":
            "Malicious natural-language instructions are stored in persistent AI memory.",
        "impact":
            "Prompt compromise may persist beyond the originating session.",
        "likelihood": 5,
        "impact_score": 5,
    },

    {
        "threat_id": "MEM-THR-2803",
        "name": "RAG-to-Memory Poisoning",
        "category": "MEMORY_POISONING",
        "component": "MEM-COMP-01",
        "scenario":
            "Poisoned retrieved content is persisted into long-lived memory.",
        "impact":
            "Retrieval compromise becomes persistent AI state.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "MEM-THR-2804",
        "name": "Prompt-to-Memory Poisoning",
        "category": "MEMORY_POISONING",
        "component": "MEM-COMP-01",
        "scenario":
            "Adversarial user prompt content is accepted into persistent memory.",
        "impact":
            "Attacker-controlled state may influence future sessions.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "MEM-THR-2805",
        "name": "Memory Authorization Bypass",
        "category": "WRITE_AUTHORIZATION",
        "component": "MEM-COMP-02",
        "scenario":
            "Memory persistence occurs despite missing, invalid, or denied authorization.",
        "impact":
            "Fail-open persistence allows unauthorized durable state.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "MEM-THR-2806",
        "name": "Model-Generated Memory Approval",
        "category": "AUTHORITY_CONFUSION",
        "component": "MEM-COMP-02",
        "scenario":
            "Model output claims that a memory write is approved and the system accepts the claim.",
        "impact":
            "Generated text may become false authorization evidence.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "MEM-THR-2807",
        "name": "Persistent Memory Record Tampering",
        "category": "INTEGRITY",
        "component": "MEM-COMP-03",
        "scenario":
            "Stored memory records are modified without authorization.",
        "impact":
            "Future model behavior may be influenced by corrupted state.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "MEM-THR-2808",
        "name": "Unauthorized Memory Record Insertion",
        "category": "INTEGRITY",
        "component": "MEM-COMP-03",
        "scenario":
            "Attacker inserts new memory records directly into the store.",
        "impact":
            "False or malicious state becomes persistent.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "MEM-THR-2809",
        "name": "Memory Record Deletion",
        "category": "INTEGRITY",
        "component": "MEM-COMP-03",
        "scenario":
            "Trusted persistent memory is deleted or selectively removed.",
        "impact":
            "Integrity and continuity of trusted AI state may be lost.",
        "likelihood": 3,
        "impact_score": 4,
    },

    {
        "threat_id": "MEM-THR-2810",
        "name": "Sensitive Data Persistence",
        "category": "SENSITIVE_INFORMATION",
        "component": "MEM-COMP-03",
        "scenario":
            "Sensitive prompt, RAG, identity, credential, or business information is stored unnecessarily.",
        "impact":
            "Confidential data may persist beyond intended processing.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "MEM-THR-2811",
        "name": "Cross-User Memory Disclosure",
        "category": "SENSITIVE_INFORMATION",
        "component": "MEM-COMP-05",
        "scenario":
            "Memory from one user is returned to another user.",
        "impact":
            "Confidential cross-user information may be exposed.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "MEM-THR-2812",
        "name": "Cross-Tenant Memory Disclosure",
        "category": "SENSITIVE_INFORMATION",
        "component": "MEM-COMP-05",
        "scenario":
            "Persistent state from one tenant is retrieved in another tenant context.",
        "impact":
            "Tenant isolation may fail.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "MEM-THR-2813",
        "name": "Cross-Session Poison Activation",
        "category": "CROSS_SESSION_PROPAGATION",
        "component": "MEM-COMP-05",
        "scenario":
            "Malicious state written in one session is retrieved during a later session.",
        "impact":
            "Attack persistence survives the original interaction.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "MEM-THR-2814",
        "name": "Cross-Agent Memory Propagation",
        "category": "CROSS_AGENT_PROPAGATION",
        "component": "MEM-COMP-05",
        "scenario":
            "Memory written by one agent influences another agent operating under a different trust context.",
        "impact":
            "Compromise may spread across autonomous components.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "MEM-THR-2815",
        "name": "Stale Trust Reuse",
        "category": "TRUST_LIFECYCLE",
        "component": "MEM-COMP-04",
        "scenario":
            "Old memory retains a trust classification that is no longer valid.",
        "impact":
            "Previously trusted state may be reused after its authority expires.",
        "likelihood": 4,
        "impact_score": 4,
    },

    {
        "threat_id": "MEM-THR-2816",
        "name": "Missing Memory Provenance",
        "category": "PROVENANCE",
        "component": "MEM-COMP-04",
        "scenario":
            "Stored memory lacks reliable source, session, agent, timestamp, or authorization metadata.",
        "impact":
            "The application cannot distinguish trusted memory from untrusted state.",
        "likelihood": 4,
        "impact_score": 4,
    },

    {
        "threat_id": "MEM-THR-2817",
        "name": "Memory Provenance Tampering",
        "category": "PROVENANCE",
        "component": "MEM-COMP-04",
        "scenario":
            "Metadata is altered to make malicious memory appear trusted.",
        "impact":
            "Compromised state may inherit false authority.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "MEM-THR-2818",
        "name": "Memory Expiration Failure",
        "category": "TRUST_LIFECYCLE",
        "component": "MEM-COMP-04",
        "scenario":
            "Memory remains active after expiry or revocation.",
        "impact":
            "Unsafe or obsolete state may continue influencing decisions.",
        "likelihood": 4,
        "impact_score": 3,
    },

    {
        "threat_id": "MEM-THR-2819",
        "name": "Memory-to-Agent Goal Hijacking",
        "category": "AGENT_INFLUENCE",
        "component": "MEM-COMP-07",
        "scenario":
            "Retrieved memory modifies the agent objective, workflow, tool, or target.",
        "impact":
            "Persistent state can redirect downstream agent behavior.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "MEM-THR-2820",
        "name": "Memory-to-Privileged Tool Escalation",
        "category": "AGENT_INFLUENCE",
        "component": "MEM-COMP-08",
        "scenario":
            "Persistent memory influences the agent or tool router to select a privileged capability.",
        "impact":
            "Stored malicious state may approach privileged execution.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "MEM-THR-2821",
        "name": "Memory-Based Target Substitution",
        "category": "EXECUTION_STEERING",
        "component": "MEM-COMP-08",
        "scenario":
            "Stored memory replaces the trusted target with a restricted or attacker-selected target.",
        "impact":
            "Legitimate workflows may be redirected toward high-impact assets.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "MEM-THR-2822",
        "name": "Memory-Generated Authorization Claim",
        "category": "AUTHORITY_CONFUSION",
        "component": "MEM-COMP-09",
        "scenario":
            "Persistent memory claims approval or authorization for a sensitive action.",
        "impact":
            "Stored natural-language state may be mistaken for execution authority.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "MEM-THR-2823",
        "name": "Memory Exhaustion",
        "category": "AVAILABILITY",
        "component": "MEM-COMP-03",
        "scenario":
            "Excessive or adversarial writes consume storage, indexing, retrieval, or context capacity.",
        "impact":
            "Memory availability, cost, latency, or retrieval quality may degrade.",
        "likelihood": 3,
        "impact_score": 3,
    },

    {
        "threat_id": "MEM-THR-2824",
        "name": "Memory Retrieval Amplification",
        "category": "AVAILABILITY",
        "component": "MEM-COMP-05",
        "scenario":
            "Adversarial state triggers excessively broad or repeated memory retrieval.",
        "impact":
            "Model context and system resources may be exhausted.",
        "likelihood": 3,
        "impact_score": 3,
    },

    {
        "threat_id": "MEM-THR-2825",
        "name": "Memory Telemetry Suppression",
        "category": "OBSERVABILITY",
        "component": "MEM-COMP-10",
        "scenario":
            "Memory reads, writes, provenance, authorization, or cross-session retrievals are not logged.",
        "impact":
            "Persistent compromise becomes difficult to detect or reconstruct.",
        "likelihood": 3,
        "impact_score": 4,
    },

    {
        "threat_id": "MEM-THR-2826",
        "name": "Memory Forensic Tampering",
        "category": "OBSERVABILITY",
        "component": "MEM-COMP-10",
        "scenario":
            "Security events describing malicious memory activity are modified or deleted.",
        "impact":
            "Investigation and attribution may be impaired.",
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
        "control_id": "MEM-CTRL-01",
        "name": "Explicit Memory Write Authorization",
        "addresses": [
            "MEM-THR-2801",
            "MEM-THR-2805",
            "MEM-THR-2806",
        ],
    },

    {
        "control_id": "MEM-CTRL-02",
        "name": "Memory Content Security Validation",
        "addresses": [
            "MEM-THR-2802",
            "MEM-THR-2803",
            "MEM-THR-2804",
        ],
    },

    {
        "control_id": "MEM-CTRL-03",
        "name": "Memory Integrity Protection",
        "addresses": [
            "MEM-THR-2807",
            "MEM-THR-2808",
            "MEM-THR-2809",
        ],
    },

    {
        "control_id": "MEM-CTRL-04",
        "name": "Sensitive Data Minimization",
        "addresses": [
            "MEM-THR-2810",
        ],
    },

    {
        "control_id": "MEM-CTRL-05",
        "name": "User / Tenant Memory Isolation",
        "addresses": [
            "MEM-THR-2811",
            "MEM-THR-2812",
        ],
    },

    {
        "control_id": "MEM-CTRL-06",
        "name": "Session & Agent Trust Binding",
        "addresses": [
            "MEM-THR-2813",
            "MEM-THR-2814",
        ],
    },

    {
        "control_id": "MEM-CTRL-07",
        "name": "Memory Provenance Metadata",
        "addresses": [
            "MEM-THR-2815",
            "MEM-THR-2816",
            "MEM-THR-2817",
        ],
    },

    {
        "control_id": "MEM-CTRL-08",
        "name": "Memory Expiry & Revocation",
        "addresses": [
            "MEM-THR-2815",
            "MEM-THR-2818",
        ],
    },

    {
        "control_id": "MEM-CTRL-09",
        "name": "Memory Treated as Non-Authoritative Context",
        "addresses": [
            "MEM-THR-2819",
            "MEM-THR-2822",
        ],
    },

    {
        "control_id": "MEM-CTRL-10",
        "name": "Independent Tool & Target Authorization",
        "addresses": [
            "MEM-THR-2820",
            "MEM-THR-2821",
            "MEM-THR-2822",
        ],
    },

    {
        "control_id": "MEM-CTRL-11",
        "name": "Memory Resource Quotas",
        "addresses": [
            "MEM-THR-2823",
            "MEM-THR-2824",
        ],
    },

    {
        "control_id": "MEM-CTRL-12",
        "name": "Complete Memory Security Telemetry",
        "addresses": [
            "MEM-THR-2825",
            "MEM-THR-2826",
        ],
    },
]


covered_threats = {
    threat_id
    for control in CONTROLS
    for threat_id in control["addresses"]
}


# ============================================================
# MEMORY ABUSE CHAINS
# ============================================================

ABUSE_CHAINS = [
    {
        "chain_id": "MEM-CHAIN-01",
        "name": "Prompt Poisoning to Persistent Compromise",
        "steps": [
            "MEM-THR-2804",
            "MEM-THR-2801",
            "MEM-THR-2802",
            "MEM-THR-2813",
        ],
        "impact":
            "Prompt-controlled state persists into future sessions.",
    },

    {
        "chain_id": "MEM-CHAIN-02",
        "name": "RAG Poisoning to Cross-Agent Propagation",
        "steps": [
            "MEM-THR-2803",
            "MEM-THR-2802",
            "MEM-THR-2814",
            "MEM-THR-2819",
        ],
        "impact":
            "Poisoned retrieval becomes persistent and influences another agent.",
    },

    {
        "chain_id": "MEM-CHAIN-03",
        "name": "Memory Poisoning to Privileged Execution",
        "steps": [
            "MEM-THR-2802",
            "MEM-THR-2813",
            "MEM-THR-2819",
            "MEM-THR-2820",
            "MEM-THR-2822",
        ],
        "impact":
            "Persistent malicious state approaches privileged execution authority.",
    },

    {
        "chain_id": "MEM-CHAIN-04",
        "name": "Provenance Tampering to Trusted-State Abuse",
        "steps": [
            "MEM-THR-2817",
            "MEM-THR-2815",
            "MEM-THR-2819",
        ],
        "impact":
            "Malicious memory is made to appear trusted and influences agent behavior.",
    },

    {
        "chain_id": "MEM-CHAIN-05",
        "name": "Cross-Tenant Memory to Sensitive Disclosure",
        "steps": [
            "MEM-THR-2812",
            "MEM-THR-2810",
        ],
        "impact":
            "Persistent state exposes confidential information across trust boundaries.",
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

poisoning_threats = [
    threat
    for threat in THREATS
    if threat["category"] == "MEMORY_POISONING"
]

cross_boundary_threats = [
    threat
    for threat in THREATS
    if threat["category"]
    in {
        "CROSS_SESSION_PROPAGATION",
        "CROSS_AGENT_PROPAGATION",
        "SENSITIVE_INFORMATION",
    }
]

agent_execution_threats = [
    threat
    for threat in THREATS
    if threat["category"]
    in {
        "AGENT_INFLUENCE",
        "EXECUTION_STEERING",
        "AUTHORITY_CONFUSION",
    }
]

provenance_lifecycle_threats = [
    threat
    for threat in THREATS
    if threat["category"]
    in {
        "PROVENANCE",
        "TRUST_LIFECYCLE",
    }
]


# ============================================================
# OUTPUT
# ============================================================

def header(title):

    print("\n" + "=" * 84)
    print(f"        {title}")
    print("=" * 84)


header("MEMORY COMPONENT MODEL")

for component in MEMORY_COMPONENTS:

    print(
        f"{component['component_id']} | "
        f"{component['trust']} | "
        f"{component['name']}"
    )


header("MEMORY THREAT REGISTER")

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


header("MEMORY THREAT CATEGORY DISTRIBUTION")

for category, count in sorted(
    category_counter.items()
):

    print(
        f"{category}: {count}"
    )


header("MEMORY THREAT PRIORITY DISTRIBUTION")

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


header("HIGH / CRITICAL MEMORY THREATS")

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


header("MEMORY POISONING THREATS")

for threat in poisoning_threats:

    print(
        f"{threat['threat_id']} | "
        f"{threat['name']}"
    )


header("CROSS-BOUNDARY MEMORY THREATS")

for threat in cross_boundary_threats:

    print(
        f"{threat['threat_id']} | "
        f"{threat['category']} | "
        f"{threat['name']}"
    )


header("MEMORY-TO-AGENT / EXECUTION THREATS")

for threat in agent_execution_threats:

    print(
        f"{threat['threat_id']} | "
        f"{threat['category']} | "
        f"{threat['name']}"
    )


header("MEMORY PROVENANCE / LIFECYCLE THREATS")

for threat in provenance_lifecycle_threats:

    print(
        f"{threat['threat_id']} | "
        f"{threat['category']} | "
        f"{threat['name']}"
    )


header("MEMORY SECURITY CONTROL MAPPING")

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


header("MEMORY ABUSE CHAINS")

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

header("MEMORY THREAT-MODEL SUMMARY")

print(
    f"Memory Components: "
    f"{len(MEMORY_COMPONENTS)}"
)

print(
    f"Memory Threat Scenarios: "
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
    f"Memory Poisoning Threats: "
    f"{len(poisoning_threats)}"
)

print(
    f"Cross-Boundary Memory Threats: "
    f"{len(cross_boundary_threats)}"
)

print(
    f"Memory-to-Agent / Execution Threats: "
    f"{len(agent_execution_threats)}"
)

print(
    f"Provenance / Lifecycle Threats: "
    f"{len(provenance_lifecycle_threats)}"
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
    f"Multi-Stage Memory Abuse Chains: "
    f"{len(ABUSE_CHAINS)}"
)


# ============================================================
# VALIDATION
# ============================================================

header("MEMORY THREAT-MODEL SECURITY CHECKS")

threat_ids = [
    threat["threat_id"]
    for threat in THREATS
]

component_ids = {
    component["component_id"]
    for component in MEMORY_COMPONENTS
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

    "Unauthorized Write Threat Identified":
        any(
            threat["name"]
            == "Unauthorized Memory Write"
            for threat in THREATS
        ),

    "Memory Poisoning Threats Identified":
        len(poisoning_threats) > 0,

    "Cross-Session Threat Identified":
        any(
            threat["category"]
            == "CROSS_SESSION_PROPAGATION"
            for threat in THREATS
        ),

    "Cross-Agent Threat Identified":
        any(
            threat["category"]
            == "CROSS_AGENT_PROPAGATION"
            for threat in THREATS
        ),

    "Sensitive Memory Threats Identified":
        any(
            threat["category"]
            == "SENSITIVE_INFORMATION"
            for threat in THREATS
        ),

    "Memory Provenance Threats Identified":
        any(
            threat["category"]
            == "PROVENANCE"
            for threat in THREATS
        ),

    "Memory Lifecycle Threats Identified":
        any(
            threat["category"]
            == "TRUST_LIFECYCLE"
            for threat in THREATS
        ),

    "Memory-to-Agent Threats Identified":
        any(
            threat["category"]
            == "AGENT_INFLUENCE"
            for threat in THREATS
        ),

    "Memory-to-Execution Threat Identified":
        any(
            threat["category"]
            == "EXECUTION_STEERING"
            for threat in THREATS
        ),

    "Authority Confusion Threat Identified":
        any(
            threat["category"]
            == "AUTHORITY_CONFUSION"
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


memory_threat_model_valid = all(
    checks.values()
)


print(
    f"\nMemory / Persistent-State Threat Model Valid: "
    f"{memory_threat_model_valid}"
)


# ============================================================
# EXPORT
# ============================================================

REPORT = {
    "lab":
        "Day 28 Lab 7",

    "title":
        "Memory & Persistent-State Threat Modeling",

    "components":
        MEMORY_COMPONENTS,

    "threats":
        THREATS,

    "controls":
        CONTROLS,

    "abuse_chains":
        ABUSE_CHAINS,

    "metrics": {
        "memory_components":
            len(MEMORY_COMPONENTS),

        "threat_scenarios":
            len(THREATS),

        "threat_categories":
            len(category_counter),

        "high_critical_threats":
            len(high_critical),

        "memory_poisoning_threats":
            len(poisoning_threats),

        "cross_boundary_threats":
            len(cross_boundary_threats),

        "memory_to_agent_execution_threats":
            len(agent_execution_threats),

        "provenance_lifecycle_threats":
            len(provenance_lifecycle_threats),

        "security_controls":
            len(CONTROLS),

        "threats_with_control_coverage":
            len(covered_threats),

        "abuse_chains":
            len(ABUSE_CHAINS),
    },

    "security_checks":
        checks,

    "memory_threat_model_valid":
        memory_threat_model_valid,
}


OUTPUT_FILE = (
    "day28-memory-persistent-state-threat-model-evidence.json"
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
    "Persistent AI memory changes the security model because model, "
    "retrieval, or user-controlled state may outlive the session in "
    "which it originated."
)

print(
    "The most dangerous memory threats occur when untrusted state can "
    "be written without authorization, retain stale or false trust, "
    "cross user, tenant, session, or agent boundaries, and later "
    "influence tool selection, targets, or authorization."
)

print(
    "Secure memory architecture should therefore treat persistent state "
    "as security-sensitive data requiring provenance, integrity, scope, "
    "expiry, authorization, isolation, and independent downstream "
    "execution controls."
)

print("\nCore Principle:")

print(
    "AI security should be designed from identified threats and trust "
    "boundaries, not added only after vulnerabilities are discovered."
)