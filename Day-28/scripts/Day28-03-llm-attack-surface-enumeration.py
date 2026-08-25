"""
Day 28 Lab 3
LLM Attack-Surface Enumeration

Purpose:
Enumerate concrete attack surfaces across the synthetic AI system
using the asset inventory and trust-boundary model established in
Labs 1 and 2.

Core Principle:
AI security should be designed from identified threats and trust
boundaries, not added only after vulnerabilities are discovered.
"""

import json
from collections import Counter, defaultdict


print(
    "\n=== Day 28 Lab 3: LLM Attack-Surface Enumeration ===\n"
)


# ============================================================
# SYSTEM
# ============================================================

SYSTEM = {
    "system_id": "AI-SYSTEM-2801",
    "name": "synthetic-enterprise-ai-assistant",
    "environment": "day28-threat-model-lab",
    "version": "v1.0.0",
}


# ============================================================
# ATTACK SURFACE CATEGORIES
# ============================================================

CATEGORIES = {
    "INPUT": "Externally or user-controlled input surfaces",
    "INSTRUCTION": "Instruction hierarchy and prompt-control surfaces",
    "RAG": "Retrieval, document and context-admission surfaces",
    "MEMORY": "Persistent AI state and memory surfaces",
    "MODEL": "Model runtime and model-control surfaces",
    "AGENT": "Agent reasoning, planning and delegation surfaces",
    "TOOL": "Tool selection, parameters and execution surfaces",
    "AUTHORIZATION": "Identity, privilege and execution authorization surfaces",
    "SECRET": "Credential, token and secret-access surfaces",
    "DOWNSTREAM": "Business-impact and downstream-service surfaces",
    "OBSERVABILITY": "Logging, telemetry and security-monitoring surfaces",
}


# ============================================================
# ATTACK SURFACES
# ============================================================

ATTACK_SURFACES = [
    {
        "surface_id": "AS-2801",
        "name": "User Prompt Entry",
        "category": "INPUT",
        "component": "input_gateway",
        "trust_boundary": "External -> Application Edge",
        "entry_point": True,
        "privileged": False,
        "persistent": False,
        "business_impact": False,
        "attack_vectors": [
            "direct_prompt_injection",
            "instruction_override",
            "malicious_payload_framing",
        ],
    },

    {
        "surface_id": "AS-2802",
        "name": "System Prompt / Instruction Hierarchy",
        "category": "INSTRUCTION",
        "component": "llm_runtime",
        "trust_boundary": "Application Edge -> AI Runtime",
        "entry_point": False,
        "privileged": False,
        "persistent": False,
        "business_impact": False,
        "attack_vectors": [
            "system_prompt_extraction",
            "instruction_confusion",
            "policy_override_attempt",
        ],
    },

    {
        "surface_id": "AS-2803",
        "name": "RAG Query Generation",
        "category": "RAG",
        "component": "retrieval_service",
        "trust_boundary": "AI Runtime -> Data & Memory",
        "entry_point": False,
        "privileged": False,
        "persistent": False,
        "business_impact": False,
        "attack_vectors": [
            "query_manipulation",
            "retrieval_scope_expansion",
            "sensitive_document_targeting",
        ],
    },

    {
        "surface_id": "AS-2804",
        "name": "RAG Knowledge Store",
        "category": "RAG",
        "component": "rag_store",
        "trust_boundary": "Data & Memory",
        "entry_point": True,
        "privileged": False,
        "persistent": True,
        "business_impact": False,
        "attack_vectors": [
            "document_poisoning",
            "malicious_content_injection",
            "source_impersonation",
            "provenance_spoofing",
        ],
    },

    {
        "surface_id": "AS-2805",
        "name": "Retrieved Context Admission",
        "category": "RAG",
        "component": "context_security_gateway",
        "trust_boundary": "Data & Memory -> AI Runtime",
        "entry_point": False,
        "privileged": False,
        "persistent": False,
        "business_impact": False,
        "attack_vectors": [
            "indirect_prompt_injection",
            "false_authority_in_context",
            "target_substitution",
        ],
    },

    {
        "surface_id": "AS-2806",
        "name": "Persistent Memory Write",
        "category": "MEMORY",
        "component": "memory_service",
        "trust_boundary": "AI Runtime -> Data & Memory",
        "entry_point": False,
        "privileged": False,
        "persistent": True,
        "business_impact": False,
        "attack_vectors": [
            "unauthorized_memory_write",
            "memory_poisoning",
            "persistent_instruction_injection",
        ],
    },

    {
        "surface_id": "AS-2807",
        "name": "Persistent Memory Read",
        "category": "MEMORY",
        "component": "memory_service",
        "trust_boundary": "Data & Memory -> AI Runtime",
        "entry_point": False,
        "privileged": False,
        "persistent": True,
        "business_impact": False,
        "attack_vectors": [
            "cross_session_poison_activation",
            "stale_trust_reuse",
            "malicious_memory_retrieval",
        ],
    },

    {
        "surface_id": "AS-2808",
        "name": "LLM Runtime",
        "category": "MODEL",
        "component": "llm_runtime",
        "trust_boundary": "AI Runtime",
        "entry_point": False,
        "privileged": False,
        "persistent": False,
        "business_impact": False,
        "attack_vectors": [
            "jailbreak",
            "policy_evasion",
            "unsafe_reasoning_influence",
            "sensitive_context_exposure",
        ],
    },

    {
        "surface_id": "AS-2809",
        "name": "Agent Planning",
        "category": "AGENT",
        "component": "agent_planner",
        "trust_boundary": "AI Runtime",
        "entry_point": False,
        "privileged": False,
        "persistent": False,
        "business_impact": False,
        "attack_vectors": [
            "goal_hijacking",
            "tool_proposal_manipulation",
            "target_substitution",
            "privilege_escalation_proposal",
        ],
    },

    {
        "surface_id": "AS-2810",
        "name": "Tool Router",
        "category": "TOOL",
        "component": "tool_router",
        "trust_boundary": "AI Runtime -> Privileged Execution",
        "entry_point": False,
        "privileged": True,
        "persistent": False,
        "business_impact": True,
        "attack_vectors": [
            "unsafe_tool_selection",
            "parameter_injection",
            "tool_confusion",
            "target_substitution",
        ],
    },

    {
        "surface_id": "AS-2811",
        "name": "Authorization Request",
        "category": "AUTHORIZATION",
        "component": "authorization_service",
        "trust_boundary": "AI Runtime -> Security Control Plane",
        "entry_point": False,
        "privileged": True,
        "persistent": False,
        "business_impact": True,
        "attack_vectors": [
            "model_generated_authority",
            "approval_spoofing",
            "identity_confusion",
        ],
    },

    {
        "surface_id": "AS-2812",
        "name": "Authorization Decision",
        "category": "AUTHORIZATION",
        "component": "authorization_service",
        "trust_boundary": "Security Control Plane -> AI Runtime",
        "entry_point": False,
        "privileged": True,
        "persistent": False,
        "business_impact": True,
        "attack_vectors": [
            "authorization_bypass",
            "fail_open_behavior",
            "decision_tampering",
        ],
    },

    {
        "surface_id": "AS-2813",
        "name": "Secret Retrieval",
        "category": "SECRET",
        "component": "secret_store",
        "trust_boundary": "Security Control Plane -> AI Runtime",
        "entry_point": False,
        "privileged": True,
        "persistent": False,
        "business_impact": True,
        "attack_vectors": [
            "credential_exposure",
            "credential_misuse",
            "secret_scope_expansion",
        ],
    },

    {
        "surface_id": "AS-2814",
        "name": "Read Record Tool",
        "category": "TOOL",
        "component": "tool_runtime",
        "trust_boundary": "AI Runtime -> Privileged Execution",
        "entry_point": False,
        "privileged": False,
        "persistent": False,
        "business_impact": True,
        "attack_vectors": [
            "unauthorized_record_access",
            "scope_expansion",
            "parameter_manipulation",
        ],
    },

    {
        "surface_id": "AS-2815",
        "name": "Delete Record Tool",
        "category": "TOOL",
        "component": "tool_runtime",
        "trust_boundary": "AI Runtime -> Privileged Execution",
        "entry_point": False,
        "privileged": True,
        "persistent": False,
        "business_impact": True,
        "attack_vectors": [
            "unauthorized_deletion",
            "privilege_escalation",
            "restricted_target_attack",
        ],
    },

    {
        "surface_id": "AS-2816",
        "name": "Restricted Record",
        "category": "DOWNSTREAM",
        "component": "record_service",
        "trust_boundary": "Privileged Execution",
        "entry_point": False,
        "privileged": True,
        "persistent": True,
        "business_impact": True,
        "attack_vectors": [
            "unauthorized_read",
            "unauthorized_update",
            "unauthorized_delete",
        ],
    },

    {
        "surface_id": "AS-2817",
        "name": "Security Telemetry",
        "category": "OBSERVABILITY",
        "component": "detection_engine",
        "trust_boundary": "AI Runtime -> Security Monitoring",
        "entry_point": False,
        "privileged": False,
        "persistent": True,
        "business_impact": False,
        "attack_vectors": [
            "log_suppression",
            "telemetry_tampering",
            "event_evasion",
            "forensic_blind_spot",
        ],
    },
]


# ============================================================
# PRIORITY SCORING
# ============================================================

def score_surface(surface):

    score = 0

    if surface["entry_point"]:
        score += 2

    if surface["privileged"]:
        score += 4

    if surface["persistent"]:
        score += 3

    if surface["business_impact"]:
        score += 4

    score += min(
        len(surface["attack_vectors"]),
        4
    )

    category_bonus = {
        "AUTHORIZATION": 3,
        "TOOL": 2,
        "MEMORY": 2,
        "RAG": 1,
        "SECRET": 3,
        "DOWNSTREAM": 3,
        "INPUT": 1,
        "INSTRUCTION": 1,
        "MODEL": 1,
        "AGENT": 2,
        "OBSERVABILITY": 1,
    }

    score += category_bonus[
        surface["category"]
    ]

    if score >= 16:
        priority = "CRITICAL"
    elif score >= 12:
        priority = "HIGH"
    elif score >= 8:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    return score, priority


for surface in ATTACK_SURFACES:

    score, priority = score_surface(
        surface
    )

    surface["risk_score"] = score
    surface["priority"] = priority


# ============================================================
# ATTACK VECTOR NORMALIZATION
# ============================================================

all_vectors = []

for surface in ATTACK_SURFACES:
    all_vectors.extend(
        surface["attack_vectors"]
    )

vector_counter = Counter(all_vectors)


# ============================================================
# ANALYSIS
# ============================================================

category_counter = Counter(
    surface["category"]
    for surface in ATTACK_SURFACES
)

priority_counter = Counter(
    surface["priority"]
    for surface in ATTACK_SURFACES
)

boundary_counter = Counter(
    surface["trust_boundary"]
    for surface in ATTACK_SURFACES
)

entry_surfaces = [
    surface
    for surface in ATTACK_SURFACES
    if surface["entry_point"]
]

persistent_surfaces = [
    surface
    for surface in ATTACK_SURFACES
    if surface["persistent"]
]

privileged_surfaces = [
    surface
    for surface in ATTACK_SURFACES
    if surface["privileged"]
]

business_impact_surfaces = [
    surface
    for surface in ATTACK_SURFACES
    if surface["business_impact"]
]

high_risk_surfaces = [
    surface
    for surface in ATTACK_SURFACES
    if surface["priority"]
    in {"HIGH", "CRITICAL"}
]


# ============================================================
# ATTACK CHAINS
# ============================================================

ABUSE_PATHS = [
    {
        "path_id": "PATH-2801",
        "name": "Prompt Injection to Privileged Execution",
        "stages": [
            "AS-2801",
            "AS-2802",
            "AS-2809",
            "AS-2810",
            "AS-2811",
            "AS-2812",
            "AS-2815",
            "AS-2816",
        ],
        "impact":
            "Unauthorized privileged business operation",
    },

    {
        "path_id": "PATH-2802",
        "name": "RAG Poisoning to Persistent Compromise",
        "stages": [
            "AS-2804",
            "AS-2805",
            "AS-2806",
            "AS-2807",
            "AS-2809",
        ],
        "impact":
            "Persistent cross-session manipulation",
    },

    {
        "path_id": "PATH-2803",
        "name": "Secret Exposure to Tool Abuse",
        "stages": [
            "AS-2813",
            "AS-2810",
            "AS-2815",
            "AS-2816",
        ],
        "impact":
            "Unauthorized downstream access or destructive action",
    },

    {
        "path_id": "PATH-2804",
        "name": "Telemetry Evasion During AI Attack",
        "stages": [
            "AS-2817",
            "AS-2812",
            "AS-2815",
            "AS-2816",
        ],
        "impact":
            "Reduced detection and forensic visibility during impact",
    },
]


# ============================================================
# OUTPUT HELPERS
# ============================================================

def header(title):

    print("\n" + "=" * 82)
    print(f"        {title}")
    print("=" * 82)


# ============================================================
# OUTPUT
# ============================================================

header("ATTACK SURFACE INVENTORY")

for surface in ATTACK_SURFACES:

    print(
        f"{surface['surface_id']} | "
        f"{surface['category']} | "
        f"{surface['priority']} | "
        f"Score={surface['risk_score']} | "
        f"{surface['name']}"
    )

    print(
        f"  Component: "
        f"{surface['component']}"
    )

    print(
        f"  Trust Boundary: "
        f"{surface['trust_boundary']}"
    )

    print(
        f"  Entry Point: "
        f"{surface['entry_point']}"
    )

    print(
        f"  Privileged: "
        f"{surface['privileged']}"
    )

    print(
        f"  Persistent: "
        f"{surface['persistent']}"
    )

    print(
        f"  Business Impact: "
        f"{surface['business_impact']}"
    )

    print(
        f"  Attack Vectors: "
        f"{surface['attack_vectors']}"
    )


header("ATTACK SURFACE CATEGORY DISTRIBUTION")

for category, count in sorted(
    category_counter.items()
):
    print(
        f"{category}: {count}"
    )


header("ATTACK SURFACE PRIORITY DISTRIBUTION")

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


header("HIGH / CRITICAL ATTACK SURFACES")

for surface in sorted(
    high_risk_surfaces,
    key=lambda item: item["risk_score"],
    reverse=True,
):

    print(
        f"{surface['surface_id']} | "
        f"{surface['priority']} | "
        f"Score={surface['risk_score']} | "
        f"{surface['name']}"
    )


header("ATTACK ENTRY POINTS")

for surface in entry_surfaces:

    print(
        f"{surface['surface_id']} | "
        f"{surface['name']}"
    )


header("PERSISTENT ATTACK SURFACES")

for surface in persistent_surfaces:

    print(
        f"{surface['surface_id']} | "
        f"{surface['name']}"
    )


header("PRIVILEGED ATTACK SURFACES")

for surface in privileged_surfaces:

    print(
        f"{surface['surface_id']} | "
        f"{surface['name']}"
    )


header("BUSINESS-IMPACT ATTACK SURFACES")

for surface in business_impact_surfaces:

    print(
        f"{surface['surface_id']} | "
        f"{surface['name']}"
    )


header("REPEATED ATTACK VECTOR THEMES")

for vector, count in sorted(
    vector_counter.items(),
    key=lambda item: (-item[1], item[0]),
):

    if count > 1:
        print(
            f"{vector}: {count} surfaces"
        )


header("PRELIMINARY ABUSE PATHS")

for path in ABUSE_PATHS:

    print(
        f"{path['path_id']} | "
        f"{path['name']}"
    )

    print(
        "  Path: "
        + " -> ".join(
            path["stages"]
        )
    )

    print(
        f"  Impact: "
        f"{path['impact']}"
    )


# ============================================================
# SUMMARY
# ============================================================

header("ATTACK-SURFACE SUMMARY")

print(
    f"Total Attack Surfaces: "
    f"{len(ATTACK_SURFACES)}"
)

print(
    f"Attack Categories: "
    f"{len(category_counter)}"
)

print(
    f"Entry Points: "
    f"{len(entry_surfaces)}"
)

print(
    f"Persistent Attack Surfaces: "
    f"{len(persistent_surfaces)}"
)

print(
    f"Privileged Attack Surfaces: "
    f"{len(privileged_surfaces)}"
)

print(
    f"Business-Impact Surfaces: "
    f"{len(business_impact_surfaces)}"
)

print(
    f"High/Critical Surfaces: "
    f"{len(high_risk_surfaces)}"
)

print(
    f"Unique Attack Vectors: "
    f"{len(vector_counter)}"
)

print(
    f"Preliminary Abuse Paths: "
    f"{len(ABUSE_PATHS)}"
)


# ============================================================
# VALIDATION
# ============================================================

header("ATTACK-SURFACE SECURITY CHECKS")

surface_ids = [
    surface["surface_id"]
    for surface in ATTACK_SURFACES
]

checks = {
    "Unique Surface IDs":
        len(surface_ids)
        == len(set(surface_ids)),

    "Prompt Surface Identified":
        any(
            surface["category"] == "INPUT"
            for surface in ATTACK_SURFACES
        ),

    "Instruction Surface Identified":
        any(
            surface["category"] == "INSTRUCTION"
            for surface in ATTACK_SURFACES
        ),

    "RAG Surfaces Identified":
        any(
            surface["category"] == "RAG"
            for surface in ATTACK_SURFACES
        ),

    "Memory Surfaces Identified":
        any(
            surface["category"] == "MEMORY"
            for surface in ATTACK_SURFACES
        ),

    "Model Surface Identified":
        any(
            surface["category"] == "MODEL"
            for surface in ATTACK_SURFACES
        ),

    "Agent Surface Identified":
        any(
            surface["category"] == "AGENT"
            for surface in ATTACK_SURFACES
        ),

    "Tool Surfaces Identified":
        any(
            surface["category"] == "TOOL"
            for surface in ATTACK_SURFACES
        ),

    "Authorization Surfaces Identified":
        any(
            surface["category"] == "AUTHORIZATION"
            for surface in ATTACK_SURFACES
        ),

    "Secret Surface Identified":
        any(
            surface["category"] == "SECRET"
            for surface in ATTACK_SURFACES
        ),

    "Downstream Business Surface Identified":
        any(
            surface["category"] == "DOWNSTREAM"
            for surface in ATTACK_SURFACES
        ),

    "Observability Surface Identified":
        any(
            surface["category"] == "OBSERVABILITY"
            for surface in ATTACK_SURFACES
        ),

    "Persistent Surfaces Identified":
        len(persistent_surfaces) > 0,

    "Privileged Surfaces Identified":
        len(privileged_surfaces) > 0,

    "Business Impact Surfaces Identified":
        len(business_impact_surfaces) > 0,

    "Multi-Stage Abuse Paths Identified":
        len(ABUSE_PATHS) > 0,
}


for check, result in checks.items():
    print(
        f"{check}: {result}"
    )


attack_surface_model_valid = all(
    checks.values()
)


print(
    f"\nAttack Surface Model Valid: "
    f"{attack_surface_model_valid}"
)


# ============================================================
# EXPORT
# ============================================================

REPORT = {
    "lab":
        "Day 28 Lab 3",

    "title":
        "LLM Attack-Surface Enumeration",

    "system":
        SYSTEM,

    "categories":
        CATEGORIES,

    "attack_surfaces":
        ATTACK_SURFACES,

    "abuse_paths":
        ABUSE_PATHS,

    "metrics": {
        "total_attack_surfaces":
            len(ATTACK_SURFACES),

        "attack_categories":
            len(category_counter),

        "entry_points":
            len(entry_surfaces),

        "persistent_surfaces":
            len(persistent_surfaces),

        "privileged_surfaces":
            len(privileged_surfaces),

        "business_impact_surfaces":
            len(business_impact_surfaces),

        "high_critical_surfaces":
            len(high_risk_surfaces),

        "unique_attack_vectors":
            len(vector_counter),

        "preliminary_abuse_paths":
            len(ABUSE_PATHS),
    },

    "security_checks":
        checks,

    "attack_surface_model_valid":
        attack_surface_model_valid,
}


OUTPUT_FILE = (
    "day28-attack-surface-enumeration-evidence.json"
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


print(
    "\nEvidence written to:"
)

print(
    OUTPUT_FILE
)


# ============================================================
# INTERPRETATION
# ============================================================

print("\nSecurity Interpretation:")

print(
    "The attack-surface inventory converts architectural trust "
    "boundaries into concrete opportunities for manipulation, "
    "persistence, privilege escalation, credential misuse, "
    "execution abuse, downstream impact, and observability evasion."
)

print(
    "The LLM itself is only one attack surface. Retrieval, memory, "
    "agents, tools, authorization, secrets, privileged business "
    "operations, and security telemetry all create independent "
    "security-relevant surfaces."
)

print(
    "The identified surfaces and preliminary abuse paths now provide "
    "the input for structured STRIDE-style AI threat enumeration."
)

print("\nCore Principle:")

print(
    "AI security should be designed from identified threats and trust "
    "boundaries, not added only after vulnerabilities are discovered."
)