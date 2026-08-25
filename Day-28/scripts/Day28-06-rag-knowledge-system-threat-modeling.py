"""
Day 28 Lab 6
RAG & Knowledge-System Threat Modeling

Purpose:
Model threats against Retrieval-Augmented Generation systems,
knowledge stores, document provenance, retrieval scope, embeddings,
context admission and RAG-to-agent abuse paths.

Core Principle:
AI security should be designed from identified threats and trust
boundaries, not added only after vulnerabilities are discovered.
"""

import json
from collections import Counter


print(
    "\n=== Day 28 Lab 6: "
    "RAG & Knowledge-System Threat Modeling ===\n"
)


# ============================================================
# RAG COMPONENTS
# ============================================================

RAG_COMPONENTS = [
    {
        "component_id": "RAG-COMP-01",
        "name": "Knowledge Source",
        "trust": "mixed",
    },
    {
        "component_id": "RAG-COMP-02",
        "name": "Document Ingestion Pipeline",
        "trust": "internal",
    },
    {
        "component_id": "RAG-COMP-03",
        "name": "Embedding Pipeline",
        "trust": "internal",
    },
    {
        "component_id": "RAG-COMP-04",
        "name": "Vector / Knowledge Store",
        "trust": "internal",
    },
    {
        "component_id": "RAG-COMP-05",
        "name": "Retrieval Query Generator",
        "trust": "internal",
    },
    {
        "component_id": "RAG-COMP-06",
        "name": "Retriever",
        "trust": "internal",
    },
    {
        "component_id": "RAG-COMP-07",
        "name": "Retrieved Document Set",
        "trust": "mixed",
    },
    {
        "component_id": "RAG-COMP-08",
        "name": "Context Admission Gateway",
        "trust": "security_controlled",
    },
    {
        "component_id": "RAG-COMP-09",
        "name": "LLM Runtime",
        "trust": "trusted_runtime",
    },
    {
        "component_id": "RAG-COMP-10",
        "name": "Agent Planner",
        "trust": "trusted_runtime",
    },
]


# ============================================================
# RAG THREATS
# ============================================================

THREATS = [
    {
        "threat_id": "RAG-THR-2801",
        "name": "Malicious Source Ingestion",
        "category": "SOURCE_POISONING",
        "component": "RAG-COMP-01",
        "scenario":
            "Attacker-controlled or compromised content is accepted into the knowledge pipeline.",
        "impact":
            "Poisoned data may become available for later retrieval.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "RAG-THR-2802",
        "name": "Trusted Source Impersonation",
        "category": "PROVENANCE_SPOOFING",
        "component": "RAG-COMP-01",
        "scenario":
            "Malicious content falsely claims to originate from a trusted source.",
        "impact":
            "Untrusted content may inherit false authority.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "RAG-THR-2803",
        "name": "Document Tampering During Ingestion",
        "category": "INGESTION_TAMPERING",
        "component": "RAG-COMP-02",
        "scenario":
            "Documents are modified between source acquisition and indexing.",
        "impact":
            "Knowledge integrity may be compromised before retrieval.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "RAG-THR-2804",
        "name": "Malicious Embedded Instructions",
        "category": "INDIRECT_PROMPT_INJECTION",
        "component": "RAG-COMP-02",
        "scenario":
            "Documents contain natural-language instructions designed to control the LLM when retrieved.",
        "impact":
            "Retrieved data may become instruction-like attack content.",
        "likelihood": 5,
        "impact_score": 5,
    },

    {
        "threat_id": "RAG-THR-2805",
        "name": "Embedding Manipulation",
        "category": "EMBEDDING_ATTACK",
        "component": "RAG-COMP-03",
        "scenario":
            "Content is crafted to manipulate semantic similarity or retrieval ranking.",
        "impact":
            "Malicious documents may be preferentially retrieved.",
        "likelihood": 3,
        "impact_score": 4,
    },

    {
        "threat_id": "RAG-THR-2806",
        "name": "Vector Store Poisoning",
        "category": "STORE_POISONING",
        "component": "RAG-COMP-04",
        "scenario":
            "Stored embeddings or documents are modified without authorization.",
        "impact":
            "Persistent retrieval integrity is compromised.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "RAG-THR-2807",
        "name": "Unauthorized Document Insertion",
        "category": "STORE_POISONING",
        "component": "RAG-COMP-04",
        "scenario":
            "Attacker inserts malicious or false documents into the knowledge store.",
        "impact":
            "Poisoned content may influence many future sessions.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "RAG-THR-2808",
        "name": "Stale or Revoked Knowledge Reuse",
        "category": "DATA_FRESHNESS",
        "component": "RAG-COMP-04",
        "scenario":
            "Expired, revoked, or outdated documents remain retrievable.",
        "impact":
            "The model may act on obsolete policy or unsafe business state.",
        "likelihood": 4,
        "impact_score": 3,
    },

    {
        "threat_id": "RAG-THR-2809",
        "name": "Retrieval Query Manipulation",
        "category": "QUERY_MANIPULATION",
        "component": "RAG-COMP-05",
        "scenario":
            "User or model state manipulates the query toward unauthorized or attacker-selected content.",
        "impact":
            "Retrieval scope may deviate from the trusted task.",
        "likelihood": 4,
        "impact_score": 4,
    },

    {
        "threat_id": "RAG-THR-2810",
        "name": "Sensitive Scope Expansion",
        "category": "ACCESS_CONTROL",
        "component": "RAG-COMP-05",
        "scenario":
            "Retrieval query requests documents outside the user's authorized information scope.",
        "impact":
            "Sensitive or restricted documents may be returned.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "RAG-THR-2811",
        "name": "Cross-Tenant Retrieval",
        "category": "ACCESS_CONTROL",
        "component": "RAG-COMP-06",
        "scenario":
            "Retriever returns content belonging to another tenant, user or business context.",
        "impact":
            "Confidentiality isolation may fail.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "RAG-THR-2812",
        "name": "Retriever Ranking Manipulation",
        "category": "RETRIEVAL_MANIPULATION",
        "component": "RAG-COMP-06",
        "scenario":
            "Attacker-controlled content is optimized to dominate retrieval results.",
        "impact":
            "Malicious context may crowd out legitimate evidence.",
        "likelihood": 4,
        "impact_score": 4,
    },

    {
        "threat_id": "RAG-THR-2813",
        "name": "False Authority in Retrieved Context",
        "category": "CONTEXT_AUTHORITY",
        "component": "RAG-COMP-07",
        "scenario":
            "Retrieved document claims administrator approval, policy authority or execution permission.",
        "impact":
            "Untrusted retrieval data may be mistaken for authority.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "RAG-THR-2814",
        "name": "Target Substitution in Retrieved Context",
        "category": "CONTEXT_MANIPULATION",
        "component": "RAG-COMP-07",
        "scenario":
            "Retrieved content instructs the model or agent to operate on a different target.",
        "impact":
            "Legitimate workflows may be redirected toward restricted assets.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "RAG-THR-2815",
        "name": "Retrieved Sensitive Data Disclosure",
        "category": "SENSITIVE_INFORMATION",
        "component": "RAG-COMP-07",
        "scenario":
            "Retrieved documents contain information the user is not authorized to receive.",
        "impact":
            "Sensitive business information may enter model output.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "RAG-THR-2816",
        "name": "Context Admission Without Provenance",
        "category": "CONTEXT_ADMISSION",
        "component": "RAG-COMP-08",
        "scenario":
            "Retrieved context is admitted without verifying source, integrity, trust or scope.",
        "impact":
            "Untrusted context may enter the model runtime unchecked.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "RAG-THR-2817",
        "name": "Context Admission Fail-Open",
        "category": "CONTEXT_ADMISSION",
        "component": "RAG-COMP-08",
        "scenario":
            "Context is accepted when provenance validation is missing or fails.",
        "impact":
            "Security-control failure may allow poisoned content into runtime.",
        "likelihood": 3,
        "impact_score": 5,
    },

    {
        "threat_id": "RAG-THR-2818",
        "name": "Retrieved Instruction Execution",
        "category": "CONTEXT_TO_INSTRUCTION",
        "component": "RAG-COMP-09",
        "scenario":
            "LLM interprets retrieved natural language as instructions rather than data.",
        "impact":
            "RAG content may override trusted task intent.",
        "likelihood": 5,
        "impact_score": 5,
    },

    {
        "threat_id": "RAG-THR-2819",
        "name": "RAG-to-Memory Persistence",
        "category": "PERSISTENCE",
        "component": "RAG-COMP-09",
        "scenario":
            "Retrieved malicious state is persisted into AI memory.",
        "impact":
            "RAG compromise may survive beyond the originating session.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "RAG-THR-2820",
        "name": "RAG-to-Agent Goal Hijacking",
        "category": "AGENT_INFLUENCE",
        "component": "RAG-COMP-10",
        "scenario":
            "Retrieved context manipulates agent objective, tool selection or target.",
        "impact":
            "Poisoned knowledge may steer downstream execution.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "RAG-THR-2821",
        "name": "RAG-to-Privileged Tool Escalation",
        "category": "AGENT_INFLUENCE",
        "component": "RAG-COMP-10",
        "scenario":
            "Retrieved content influences the agent to propose a privileged tool.",
        "impact":
            "Untrusted knowledge may approach execution authority.",
        "likelihood": 4,
        "impact_score": 5,
    },

    {
        "threat_id": "RAG-THR-2822",
        "name": "RAG Resource Exhaustion",
        "category": "AVAILABILITY",
        "component": "RAG-COMP-06",
        "scenario":
            "Adversarial retrieval patterns trigger excessive queries, large result sets or expensive processing.",
        "impact":
            "Retrieval availability, cost and latency may be affected.",
        "likelihood": 3,
        "impact_score": 3,
    },

    {
        "threat_id": "RAG-THR-2823",
        "name": "Retrieval Telemetry Suppression",
        "category": "OBSERVABILITY",
        "component": "RAG-COMP-06",
        "scenario":
            "Document IDs, provenance, queries or admission decisions are not logged.",
        "impact":
            "RAG attacks become difficult to investigate or detect.",
        "likelihood": 3,
        "impact_score": 4,
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
        "control_id": "RAG-CTRL-01",
        "name": "Trusted Source Allowlisting",
        "addresses": [
            "RAG-THR-2801",
            "RAG-THR-2802",
        ],
    },

    {
        "control_id": "RAG-CTRL-02",
        "name": "Document Integrity & Provenance Validation",
        "addresses": [
            "RAG-THR-2802",
            "RAG-THR-2803",
            "RAG-THR-2816",
            "RAG-THR-2817",
        ],
    },

    {
        "control_id": "RAG-CTRL-03",
        "name": "Indirect Prompt-Injection Scanning",
        "addresses": [
            "RAG-THR-2804",
            "RAG-THR-2818",
        ],
    },

    {
        "control_id": "RAG-CTRL-04",
        "name": "Embedding / Index Integrity Monitoring",
        "addresses": [
            "RAG-THR-2805",
            "RAG-THR-2806",
            "RAG-THR-2807",
        ],
    },

    {
        "control_id": "RAG-CTRL-05",
        "name": "Document Lifecycle & Freshness Control",
        "addresses": [
            "RAG-THR-2808",
        ],
    },

    {
        "control_id": "RAG-CTRL-06",
        "name": "Task-Bound Retrieval Scope",
        "addresses": [
            "RAG-THR-2809",
            "RAG-THR-2810",
            "RAG-THR-2811",
        ],
    },

    {
        "control_id": "RAG-CTRL-07",
        "name": "Retrieval Ranking Abuse Detection",
        "addresses": [
            "RAG-THR-2812",
        ],
    },

    {
        "control_id": "RAG-CTRL-08",
        "name": "Retrieved Context Treated as Untrusted Data",
        "addresses": [
            "RAG-THR-2813",
            "RAG-THR-2814",
            "RAG-THR-2818",
        ],
    },

    {
        "control_id": "RAG-CTRL-09",
        "name": "Document-Level Authorization",
        "addresses": [
            "RAG-THR-2810",
            "RAG-THR-2811",
            "RAG-THR-2815",
        ],
    },

    {
        "control_id": "RAG-CTRL-10",
        "name": "Authorized Memory Persistence",
        "addresses": [
            "RAG-THR-2819",
        ],
    },

    {
        "control_id": "RAG-CTRL-11",
        "name": "Independent Agent / Tool Authorization",
        "addresses": [
            "RAG-THR-2820",
            "RAG-THR-2821",
        ],
    },

    {
        "control_id": "RAG-CTRL-12",
        "name": "Retrieval Resource Limits",
        "addresses": [
            "RAG-THR-2822",
        ],
    },

    {
        "control_id": "RAG-CTRL-13",
        "name": "Complete RAG Security Telemetry",
        "addresses": [
            "RAG-THR-2823",
        ],
    },
]


covered_threats = {
    threat_id
    for control in CONTROLS
    for threat_id in control["addresses"]
}


# ============================================================
# RAG ABUSE CHAINS
# ============================================================

ABUSE_CHAINS = [
    {
        "chain_id": "RAG-CHAIN-01",
        "name": "Poisoned Document to Model Manipulation",
        "steps": [
            "RAG-THR-2801",
            "RAG-THR-2804",
            "RAG-THR-2816",
            "RAG-THR-2818",
        ],
        "impact":
            "Malicious knowledge source manipulates runtime behavior.",
    },

    {
        "chain_id": "RAG-CHAIN-02",
        "name": "RAG Poisoning to Persistent Compromise",
        "steps": [
            "RAG-THR-2807",
            "RAG-THR-2818",
            "RAG-THR-2819",
        ],
        "impact":
            "Poisoned retrieval state becomes persistent AI memory.",
    },

    {
        "chain_id": "RAG-CHAIN-03",
        "name": "RAG Authority Spoofing to Privileged Agent Action",
        "steps": [
            "RAG-THR-2813",
            "RAG-THR-2820",
            "RAG-THR-2821",
        ],
        "impact":
            "Retrieved false authority influences privileged execution planning.",
    },

    {
        "chain_id": "RAG-CHAIN-04",
        "name": "Retrieval Scope Expansion to Sensitive Disclosure",
        "steps": [
            "RAG-THR-2809",
            "RAG-THR-2810",
            "RAG-THR-2815",
        ],
        "impact":
            "Manipulated retrieval exposes restricted business information.",
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

critical_high = [
    threat
    for threat in THREATS
    if threat["priority"]
    in {"CRITICAL", "HIGH"}
]

poisoning_threats = [
    threat
    for threat in THREATS
    if threat["category"]
    in {
        "SOURCE_POISONING",
        "STORE_POISONING",
        "INDIRECT_PROMPT_INJECTION",
        "EMBEDDING_ATTACK",
    }
]

authorization_threats = [
    threat
    for threat in THREATS
    if threat["category"]
    in {
        "ACCESS_CONTROL",
        "CONTEXT_AUTHORITY",
        "CONTEXT_ADMISSION",
    }
]

agent_influence_threats = [
    threat
    for threat in THREATS
    if threat["category"]
    == "AGENT_INFLUENCE"
]


# ============================================================
# OUTPUT
# ============================================================

def header(title):

    print("\n" + "=" * 84)
    print(f"        {title}")
    print("=" * 84)


header("RAG COMPONENT MODEL")

for component in RAG_COMPONENTS:

    print(
        f"{component['component_id']} | "
        f"{component['trust']} | "
        f"{component['name']}"
    )


header("RAG THREAT REGISTER")

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


header("RAG THREAT CATEGORY DISTRIBUTION")

for category, count in sorted(
    category_counter.items()
):

    print(
        f"{category}: {count}"
    )


header("RAG THREAT PRIORITY DISTRIBUTION")

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


header("HIGH / CRITICAL RAG THREATS")

for threat in sorted(
    critical_high,
    key=lambda item: item["risk_score"],
    reverse=True,
):

    print(
        f"{threat['threat_id']} | "
        f"{threat['priority']} | "
        f"Risk={threat['risk_score']} | "
        f"{threat['name']}"
    )


header("RAG POISONING THREATS")

for threat in poisoning_threats:

    print(
        f"{threat['threat_id']} | "
        f"{threat['name']}"
    )


header("RAG AUTHORIZATION / TRUST THREATS")

for threat in authorization_threats:

    print(
        f"{threat['threat_id']} | "
        f"{threat['category']} | "
        f"{threat['name']}"
    )


header("RAG-TO-AGENT THREATS")

for threat in agent_influence_threats:

    print(
        f"{threat['threat_id']} | "
        f"{threat['name']}"
    )


header("RAG SECURITY CONTROL MAPPING")

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


header("RAG ABUSE CHAINS")

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

header("RAG THREAT-MODEL SUMMARY")

print(
    f"RAG Components: "
    f"{len(RAG_COMPONENTS)}"
)

print(
    f"RAG Threat Scenarios: "
    f"{len(THREATS)}"
)

print(
    f"Threat Categories: "
    f"{len(category_counter)}"
)

print(
    f"High/Critical Threats: "
    f"{len(critical_high)}"
)

print(
    f"Poisoning Threats: "
    f"{len(poisoning_threats)}"
)

print(
    f"Authorization / Trust Threats: "
    f"{len(authorization_threats)}"
)

print(
    f"RAG-to-Agent Threats: "
    f"{len(agent_influence_threats)}"
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
    f"Multi-Stage RAG Abuse Chains: "
    f"{len(ABUSE_CHAINS)}"
)


# ============================================================
# VALIDATION
# ============================================================

header("RAG THREAT-MODEL SECURITY CHECKS")

threat_ids = [
    threat["threat_id"]
    for threat in THREATS
]

component_ids = {
    component["component_id"]
    for component in RAG_COMPONENTS
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

    "Source Poisoning Identified":
        any(
            threat["category"]
            == "SOURCE_POISONING"
            for threat in THREATS
        ),

    "Provenance Spoofing Identified":
        any(
            threat["category"]
            == "PROVENANCE_SPOOFING"
            for threat in THREATS
        ),

    "Indirect Prompt Injection Identified":
        any(
            threat["category"]
            == "INDIRECT_PROMPT_INJECTION"
            for threat in THREATS
        ),

    "Embedding Threat Identified":
        any(
            threat["category"]
            == "EMBEDDING_ATTACK"
            for threat in THREATS
        ),

    "Vector Store Poisoning Identified":
        any(
            threat["category"]
            == "STORE_POISONING"
            for threat in THREATS
        ),

    "Retrieval Scope Threats Identified":
        any(
            threat["category"]
            == "ACCESS_CONTROL"
            for threat in THREATS
        ),

    "Context Authority Threat Identified":
        any(
            threat["category"]
            == "CONTEXT_AUTHORITY"
            for threat in THREATS
        ),

    "Sensitive Retrieval Threat Identified":
        any(
            threat["category"]
            == "SENSITIVE_INFORMATION"
            for threat in THREATS
        ),

    "RAG Persistence Threat Identified":
        any(
            threat["category"]
            == "PERSISTENCE"
            for threat in THREATS
        ),

    "RAG-to-Agent Threats Identified":
        len(agent_influence_threats) > 0,

    "Availability Threat Identified":
        any(
            threat["category"]
            == "AVAILABILITY"
            for threat in THREATS
        ),

    "Observability Threat Identified":
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


rag_threat_model_valid = all(
    checks.values()
)


print(
    f"\nRAG / Knowledge-System Threat Model Valid: "
    f"{rag_threat_model_valid}"
)


# ============================================================
# EXPORT
# ============================================================

REPORT = {
    "lab":
        "Day 28 Lab 6",

    "title":
        "RAG & Knowledge-System Threat Modeling",

    "components":
        RAG_COMPONENTS,

    "threats":
        THREATS,

    "controls":
        CONTROLS,

    "abuse_chains":
        ABUSE_CHAINS,

    "metrics": {
        "rag_components":
            len(RAG_COMPONENTS),

        "threat_scenarios":
            len(THREATS),

        "threat_categories":
            len(category_counter),

        "high_critical_threats":
            len(critical_high),

        "poisoning_threats":
            len(poisoning_threats),

        "authorization_trust_threats":
            len(authorization_threats),

        "rag_to_agent_threats":
            len(agent_influence_threats),

        "security_controls":
            len(CONTROLS),

        "threats_with_control_coverage":
            len(covered_threats),

        "abuse_chains":
            len(ABUSE_CHAINS),
    },

    "security_checks":
        checks,

    "rag_threat_model_valid":
        rag_threat_model_valid,
}


OUTPUT_FILE = (
    "day28-rag-knowledge-threat-model-evidence.json"
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
    "RAG security is a trust and provenance problem as much as a retrieval "
    "problem. A document being retrievable does not establish that it is "
    "authentic, authorized, current, safe, or entitled to influence model behavior."
)

print(
    "The most dangerous RAG abuse paths occur when poisoned or over-scoped "
    "retrieval can cross into model instruction processing, persistent memory, "
    "agent planning, privileged tool selection or sensitive-data disclosure."
)

print(
    "Secure RAG architecture should therefore validate source provenance, "
    "enforce document-level authorization, treat retrieved text as untrusted data, "
    "bind retrieval to the trusted task, constrain persistence, and independently "
    "authorize downstream agent and tool actions."
)

print("\nCore Principle:")

print(
    "AI security should be designed from identified threats and trust "
    "boundaries, not added only after vulnerabilities are discovered."
)